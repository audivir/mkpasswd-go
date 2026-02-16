// mkpasswd-go is a Go implementation of the classic `mkpasswd` utility (originally part of the Debian `whois` package, maintained by Marco d'Itri).
// It wraps the system's `crypt(3)` library to generate cryptographically strong hashed passwords.
// It supports modern hashing algorithms like yescrypt, bcrypt, and SHA-512.

package main

/*
#cgo pkg-config: libxcrypt
#include <crypt.h>
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// Version defines the application version.
const Version = "mkpasswd-go 1.0"

const (
	defaultMethod = "sha-512"
	// cryptBase64 is the standard alphabet used by crypt(3).
	cryptBase64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// methodDef defines the salt generation rules.
type methodDef struct {
	Prefix         string
	MinSaltLen     int
	MaxSaltLen     int // 0 implies no specific limit
	DefaultSaltLen int
	HasRounds      bool
	MinRounds      int
	MaxRounds      int // 0 implies no specific limit
	DefaultRounds  int
}

// knownMethods maps algorithm aliases to their definitions.
// More info: https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html
var knownMethods = map[string]methodDef{
	// Modern libxcrypt methods
	"yescrypt":      {"$y$", 0, 36, 22, true, 1, 11, 5},
	"gost-yescrypt": {"$gy$", 0, 36, 22, true, 1, 11, 5},
	"scrypt":        {"$7$", 0, 325, 22, true, 6, 11, 7},

	// Bcrypt
	"bcrypt":   {"$2b$", 22, 0, 22, true, 4, 31, 5},
	"bcrypt-a": {"$2a$", 22, 0, 22, true, 4, 31, 5},

	// SHA Crypt
	"sha512crypt": {"$6$", 0, 0, 16, true, 1000, 999999999, 5000},
	"sha256crypt": {"$5$", 0, 0, 16, true, 1000, 999999999, 5000},

	// MD5
	"sunmd5":   {"$md5$", 0, 0, 8, false, 0, 0, 0},
	"md5crypt": {"$1$", 0, 0, 8, false, 0, 0, 0},

	// Legacy
	"bsdicrypt": {"_", 4, 4, 4, true, 1, 16777215, 725},
	"descrypt":  {"", 2, 2, 2, false, 0, 0, 0},
	"nt":        {"$3$", 0, 0, 0, false, 0, 0, 0},
}

var aliases = map[string]string{
	"sha-512": "sha512crypt",
	"sha-256": "sha256crypt",
	"md5":     "md5crypt",
	"des":     "descrypt",
	"bf":      "bcrypt",
}

type config struct {
	Method   string
	Salt     string
	Rounds   int
	UseStdin bool
	Password string
	Verbose  bool
}

func main() {
	cmd := &cli.Command{
		Name:            "mkpasswd",
		Usage:           "Wraps system crypt(3) to generate passwords",
		Version:         Version,
		ArgsUsage:       "[password] [salt]",
		Flags:           buildFlags(),
		Action:          run,
		HideHelpCommand: true,
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// Only print the error, simpler than Fprintf for one-liners
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func buildFlags() []cli.Flag {
	// Pre-sort choices for help text
	choices := make([]string, 0, len(knownMethods))
	for k := range knownMethods {
		choices = append(choices, k)
	}
	sort.Strings(choices)

	return []cli.Flag{
		&cli.StringFlag{
			Name:    "method",
			Aliases: []string{"m"},
			Value:   defaultMethod,
			Usage:   "Select encryption method", // fmt.Sprintf("Select encryption method (available: %s)", strings.Join(choices, ", ")),
			Validator: func(val string) error {
				if a, ok := aliases[strings.ToLower(val)]; ok {
					val = a
				}
				if _, ok := knownMethods[strings.ToLower(val)]; !ok {
					return fmt.Errorf("invalid method %q, available: %s", val, strings.Join(choices, ", "))
				}
				return nil
			},
		},
		&cli.StringFlag{
			Name:    "salt",
			Aliases: []string{"S"},
			Usage:   "Specify the salt manually",
		},
		&cli.IntFlag{
			Name:        "rounds",
			Aliases:     []string{"R"},
			Usage:       "Specify the number of rounds (cost)",
			HideDefault: true,
			Validator: func(val int) error {
				if val < 0 {
					return errors.New("rounds must be >= 0")
				}
				return nil
			},
		},
		&cli.BoolFlag{
			Name:    "stdin",
			Aliases: []string{"s"},
			Usage:   "Read password from stdin",
		},
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"V"},
			Usage:   "Print verbose output",
		},
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() > 2 {
		return errors.New("too many arguments")
	}

	cfg := config{
		Method:   strings.ToLower(cmd.String("method")),
		Salt:     cmd.Args().Get(1), // Arg takes precedence
		Rounds:   cmd.Int("rounds"),
		UseStdin: cmd.Bool("stdin"),
		Password: cmd.Args().First(),
		Verbose:  cmd.Bool("verbose"),
	}

	// Resolve alias
	if realName, ok := aliases[cfg.Method]; ok {
		cfg.Method = realName
	}
	// Flag overrides Arg for salt if arg is empty
	if cfg.Salt == "" {
		cfg.Salt = cmd.String("salt")
	} else if cfg.Verbose && cmd.String("salt") != "" {
		fmt.Fprintln(os.Stderr, "salt argument ignored because salt option was provided")
	}

	pass, err := resolvePassword(cfg)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	def := knownMethods[cfg.Method]
	setting, err := buildSetting(cfg, def)
	if err != nil {
		return fmt.Errorf("failed to generate settings: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "using setting: %s\n", setting)
	}

	hash, err := crypt(pass, setting)
	if err != nil {
		return fmt.Errorf("crypt failed: %w", err)
	}

	fmt.Println(hash)
	return nil
}

// buildSetting constructs the salt/settings string.
func buildSetting(cfg config, def methodDef) (string, error) {
	// 1. If user provided a full setting string ($...), use it.
	if cfg.Salt != "" && (strings.HasPrefix(cfg.Salt, "$") || strings.HasPrefix(cfg.Salt, "_")) {
		return cfg.Salt, nil
	}

	// 2. Validate/Normalize Rounds
	if def.HasRounds {
		if cfg.Rounds == 0 {
			cfg.Rounds = def.DefaultRounds
		}
		if cfg.Rounds < def.MinRounds || (def.MaxRounds > 0 && cfg.Rounds > def.MaxRounds) {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "rounds %d out of range for %s, using default %d\n", cfg.Rounds, cfg.Method, def.DefaultRounds)
			}
			cfg.Rounds = def.DefaultRounds
		}
	} else if cfg.Rounds > 0 && cfg.Verbose {
		fmt.Fprintf(os.Stderr, "rounds ignored for method %s\n", cfg.Method)
	}

	// 3. Handle specific formatting logic for complex prefixes
	// Note: We construct the 'prefix' passed to crypt_gensalt.
	// For most, it's just "$6$", but for some (like rounds=), we must pre-format.
	var prefixBuilder strings.Builder
	prefixBuilder.WriteString(def.Prefix)

	if def.HasRounds {
		switch {
		case strings.HasPrefix(def.Prefix, "$2"): // Bcrypt
			fmt.Fprintf(&prefixBuilder, "%02d$", cfg.Rounds)
		case strings.HasPrefix(def.Prefix, "$y$"), strings.HasPrefix(def.Prefix, "$gy$"):
			// yescrypt mapping (1-11 -> params)
			params := []string{"75", "85", "7T", "8T", "9T", "AT", "BT", "CT", "DT", "ET", "FT"}
			if cfg.Rounds >= 1 && cfg.Rounds <= len(params) {
				fmt.Fprintf(&prefixBuilder, "j%s$", params[cfg.Rounds-1])
			}
		case strings.HasPrefix(def.Prefix, "$7$"): // Scrypt
			if idx := cfg.Rounds - 6; idx >= 0 && idx < 6 {
				fmt.Fprintf(&prefixBuilder, "%cU..../....", "BCDEFG"[idx])
			}
		case strings.HasPrefix(def.Prefix, "_"): // BSDi
			prefixBuilder.WriteString(intToCryptBase64(uint32(cfg.Rounds)))
		case strings.HasPrefix(def.Prefix, "$5$"), strings.HasPrefix(def.Prefix, "$6$"):
			if cfg.Rounds != 5000 {
				fmt.Fprintf(&prefixBuilder, "rounds=%d$", cfg.Rounds)
			}
		}
	}

	// 4. Handle Salt
	// If salt is "?" or empty, we generate it. If it's a raw string, we use it.
	if cfg.Salt != "" && cfg.Salt != "?" {
		// User provided raw salt characters, append to prefix
		return prefixBuilder.String() + cfg.Salt, nil
	}

	// Generate salt using libcrypt
	if cfg.Verbose {
		fmt.Fprintln(os.Stderr, "generating random salt")
	}

	saltLen := def.DefaultSaltLen
	// Calculate remaining salt length needed (subtracting what we already built)
	// Note: crypt_gensalt usually takes the raw byte count desired.
	// We use 32 bytes of entropy to be safe.
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}

	return cryptGenSalt(prefixBuilder.String(), uint64(cfg.Rounds), entropy, int32(saltLen))
}

func resolvePassword(cfg config) (string, error) {
	// Check argument first
	if cfg.Password != "" {
		return cfg.Password, nil
	}

	// Check stdin/pipe
	stat, _ := os.Stdin.Stat()
	isPipe := (stat.Mode() & os.ModeCharDevice) == 0

	if cfg.UseStdin || isPipe {
		if cfg.Verbose {
			fmt.Fprintln(os.Stderr, "reading password from stdin")
		}
		reader := bufio.NewReader(os.Stdin)
		pass, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(pass, "\r\n"), nil
	}

	// Interactive
	fmt.Fprint(os.Stderr, "password: ")
	p1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	fmt.Fprint(os.Stderr, "confirm password: ")
	p2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}

	if string(p1) != string(p2) {
		return "", errors.New("passwords do not match")
	}

	return string(p1), nil
}

// -- CGo Wrappers --

func crypt(pass, setting string) (string, error) {
	cPass := C.CString(pass)
	cSetting := C.CString(setting)
	defer C.free(unsafe.Pointer(cPass))
	defer C.free(unsafe.Pointer(cSetting))

	cResult, err := C.crypt(cPass, cSetting)
	if cResult == nil {
		return "", err
	}
	return C.GoString(cResult), nil
}

func cryptGenSalt(prefix string, rounds uint64, entropy []byte, length int32) (string, error) {
	cPrefix := C.CString(prefix)
	defer C.free(unsafe.Pointer(cPrefix))

	// Pass pointer to byte slice, not CString
	// C.crypt_gensalt expects raw bytes, possibly containing nulls.
	cEntropy := (*C.char)(unsafe.Pointer(&entropy[0]))

	cResult, err := C.crypt_gensalt(cPrefix, C.ulong(rounds), cEntropy, C.int(length))
	if cResult == nil {
		return "", fmt.Errorf("crypt_gensalt failed: %v", err)
	}
	return C.GoString(cResult), nil
}

// intToCryptBase64 converts a uint32 to 4-char base64 (used for BSDi crypt).
func intToCryptBase64(n uint32) string {
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		out[i] = cryptBase64[n&0x3f]
		n >>= 6
	}
	return string(out)
}
