package main

import "testing"

var testCases = []struct {
	Desc     string
	Password string
	Salt     string
	Hash     string
}{
	{"SHA-512 Default | Pwd: password...", "password", "$6$OsI5EjZSn1wS9JZQ", "$6$OsI5EjZSn1wS9JZQ$rZcLtjN/mW21Uk/pwhdZraqqQoOrYBAkVb.XpPoBFeCcmSwH4A5j9y9cxlE4cMNjwybNtEafJDUDm/lAjh6BV0"},
	{"SHA-512 Default | Pwd: ...", "", "$6$TtMq1Z.6I.7pPWh/", "$6$TtMq1Z.6I.7pPWh/$Sp6b6VLK/gpmBe6p6FczoZQ.BID/BxDgBrYjHIrmkwcPES4mS0zq2cTgRzDhJojR//zEUxer2ArzukZ.cJl5g."},
	{"SHA-512 Default | Pwd: correct-ho...", "correct-horse-battery-staple", "$6$pYu0Dssp8F9ArfO0", "$6$pYu0Dssp8F9ArfO0$eFg9slYgJobwVlBwIZ4CO7aKiAkX5OTSHlPO5pG37A9Xx7d1q8XKcU1ex/GpXkuMspQmOQmB6apUExU8cfwAo/"},
	{"SHA-512 Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$6$fUUWALIvJsgkAP4D", "$6$fUUWALIvJsgkAP4D$5o/yitU7j4K/g2/Bz1lDQgUsIbNoWJgaNUytiE1qFGH34wvHLZ8ntxauq7EG3ST1nB0DvLC9qdcmYekSUJP/X0"},
	{"SHA-512 Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$6$qOK7I8PYmVKPvRQT", "$6$qOK7I8PYmVKPvRQT$hGbPREr6hcZnzZT2YGQTk31m2G07gWw6w/DFWB5NMoCgKgVGgqRQd785eIgOPf5J.6TOoI9.AWXY5eQpSA57G0"},
	{"SHA-512 Low Rounds | Pwd: password...", "password", "$6$rounds=1000$HNcbUb7a/tFalRyk", "$6$rounds=1000$HNcbUb7a/tFalRyk$z0XOBSj8wNNv4XVVdBbXxIdi2xXmnBVjbNf3/DImWZ7AHQrLtPixMOnYFgkyWFSdJ5HnsXVFIkKYqDr1gFice."},
	{"SHA-512 Low Rounds | Pwd: ...", "", "$6$rounds=1000$ZHKSd0pvTXOs3JEq", "$6$rounds=1000$ZHKSd0pvTXOs3JEq$s7S4ZaWUeAIz4ol5MTuF8ViC7EZj39xbmpOOa7MOOlZfRdrIgTg4A4CXJoAfKHOGT2do.aGK3A5BWD5z5eQzQ."},
	{"SHA-512 Low Rounds | Pwd: correct-ho...", "correct-horse-battery-staple", "$6$rounds=1000$WmAZyWM62XLA2fhC", "$6$rounds=1000$WmAZyWM62XLA2fhC$w7W4QJBQOYFBkjBnwxn4JAR1xHC5t4U6KRng1Ij.9lyqjPGeGv5VKPuf30AR/biolD4xcrM/gDlznuvqpREBE1"},
	{"SHA-512 Low Rounds | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$6$rounds=1000$BmtNAW0jw7GZ8rEx", "$6$rounds=1000$BmtNAW0jw7GZ8rEx$KJBoxyS5kfoakSideMlY0Lri0mNqGBpYFiXg94sRYaeIbOSUD2Uq6Vl70guVkyPDqrvFi/3pc5V85wEyxbFAi."},
	{"SHA-512 Low Rounds | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$6$rounds=1000$LdrRlzvnNlfkoj9t", "$6$rounds=1000$LdrRlzvnNlfkoj9t$uCYEj97YvO/Tl0mD63gFVcwDHEbmp2f69y7I5UYPoSHwWXrzJQbqiR0uj8vrXxOQZ9cqPePACA83byrYsTexl1"},
	{"SHA-512 High Rounds | Pwd: password...", "password", "$6$rounds=10000$81QcL3Emd7Oi1SIJ", "$6$rounds=10000$81QcL3Emd7Oi1SIJ$kHBRvH0ubJAyQMS6ZdHqIYAH6WsCozzN0IqbqclCGO5AGpD54eTIYvqqxu829MypCOMbGhKRAtoHUwB1.OscE."},
	{"SHA-512 High Rounds | Pwd: ...", "", "$6$rounds=10000$c5WhnliCiIcLMIRM", "$6$rounds=10000$c5WhnliCiIcLMIRM$BiAGTMQyT2kCWlCQid8gQ/7HXQh2C5OWUsO7wDrj4ZYmflMqGfnV/ZGyeZw7DkoMTpyOYrTYMtwni/eSNTdWN/"},
	{"SHA-512 High Rounds | Pwd: correct-ho...", "correct-horse-battery-staple", "$6$rounds=10000$sJXeggG9F/xOFFOj", "$6$rounds=10000$sJXeggG9F/xOFFOj$c6804Nc3Eu.r31l.CkQ.uwIhKGU2Sl/ytdcgi2IMikWM14z//DbYA9ew3ejCaoMrAr6QKyeJcK8zFo3qTlPty0"},
	{"SHA-512 High Rounds | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$6$rounds=10000$ZLcmqJVaDwzHUZsp", "$6$rounds=10000$ZLcmqJVaDwzHUZsp$AXwxo3uzrDNuU8Ul0NZjZmgZ6quR1oVnoRWq0/og2rxnYj0/Zorc979cXTwS89tubAQe35bVMq4YpfIRwF3WW1"},
	{"SHA-512 High Rounds | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$6$rounds=10000$2DK7XVf4I/pUz7CI", "$6$rounds=10000$2DK7XVf4I/pUz7CI$dFBan53uoEpfMAcrSEyKOaAHsQL.XYYjYIZDtlj8bodz2n1Cs1FfXI8RW2pFL5JhooeO/WU97vGWOrb9NEWpd1"},
	{"SHA-512 Custom Salt | Pwd: password...", "password", "$6$customsalt", "$6$customsalt$DjuO5fYEr9DGjREqORtPB.DCqRp8qD19tf41p9Pz11EiF2HkMnGJqnkju8P5EPBx/VOXEduqkwNPU2/M6GHhI1"},
	{"SHA-512 Custom Salt | Pwd: ...", "", "$6$customsalt", "$6$customsalt$U87hVn88tHenskLT5TaDelPLrWpr/0AGHMu/tYEzeDA5/ClWn8AXNElnTdFggQF0QERKgpdHDZkIpkgxHAdfz1"},
	{"SHA-512 Custom Salt | Pwd: correct-ho...", "correct-horse-battery-staple", "$6$customsalt", "$6$customsalt$Op4tqNimUwKy9f2J0wJRl4gBZlTY.xCLPMVFZj.wCmgVKxfWEgFMJ30hKW52G6tyKMK8UahgZnSQ4CFGlpp2L/"},
	{"SHA-512 Custom Salt | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$6$customsalt", "$6$customsalt$4n6RKNCSIgKB.m5EHC7mz/KCTFRy8qFS0iAdz7cpNvOocSSggl8yeK3UaPodWlyR2MSQvGoltDlWV177bO1gF1"},
	{"SHA-512 Custom Salt | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$6$customsalt", "$6$customsalt$0Tx82XVom2FPe9ooj7bNeNF.3505Hsh4DiML4tAKgIPwdoFJ9cju0vY.GT11419PXCOL.pnNZvtK0D0I37xIy/"},
	{"SHA-256 Default | Pwd: password...", "password", "$5$q9dqVmyaawrhCFAF", "$5$q9dqVmyaawrhCFAF$FPuVTYbELyk8VcRoBtdnC9iKQfubCuLSqbTNIe2j2T4"},
	{"SHA-256 Default | Pwd: ...", "", "$5$TL09dzqltgb8jbXr", "$5$TL09dzqltgb8jbXr$Z2BSf58a2DDKauzTi4sUmB1wjya/HpB3lDBUNA1xaq7"},
	{"SHA-256 Default | Pwd: correct-ho...", "correct-horse-battery-staple", "$5$E5ZH5rdNM8Rf/rq6", "$5$E5ZH5rdNM8Rf/rq6$EhDDjSKLTv3vQxSsw9nzBJHH2qoXhTSFJdRpLbtqZlC"},
	{"SHA-256 Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$5$0oeKlEjP4AuUBZS6", "$5$0oeKlEjP4AuUBZS6$Nbmy04csrtFuB.bBx3v3.aOGSlUK6V7ndgWGuqMw0W/"},
	{"SHA-256 Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$5$dO8eMz5n3jlneFWB", "$5$dO8eMz5n3jlneFWB$aumfXEcCakEd.8nshqacmlVuVrYmQH.Yp8tu/Arrtq5"},
	{"SHA-256 Rounds+Salt | Pwd: password...", "password", "$5$rounds=5000$somesalt123", "$5$rounds=5000$somesalt123$yMHvgxG9H8N122Vil9gY0D5izCaWz/sFxpborDeOxA0"},
	{"SHA-256 Rounds+Salt | Pwd: ...", "", "$5$rounds=5000$somesalt123", "$5$rounds=5000$somesalt123$DlpnsYAxuiFWCKcfQieMgLDKMrKpA7Ke0F5zEMsD5WA"},
	{"SHA-256 Rounds+Salt | Pwd: correct-ho...", "correct-horse-battery-staple", "$5$rounds=5000$somesalt123", "$5$rounds=5000$somesalt123$TdPdGwb7i31VC58RJZOOe13KN2RiR7iphsvtIVjFk43"},
	{"SHA-256 Rounds+Salt | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$5$rounds=5000$somesalt123", "$5$rounds=5000$somesalt123$iOQA5M14tzxUUrusA/xSqoLMfcHyPCOV72nl40IT.E1"},
	{"SHA-256 Rounds+Salt | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$5$rounds=5000$somesalt123", "$5$rounds=5000$somesalt123$AKnXg1j2uJY3FPA4PifraqObh9IBbZRQ8X3wnHe3Zg0"},
	{"MD5 Default | Pwd: password...", "password", "$1$k34opAQM", "$1$k34opAQM$f2Cia2xu7jddwpMjkf54e0"},
	{"MD5 Default | Pwd: ...", "", "$1$DqOyTZDg", "$1$DqOyTZDg$qBquMEjgqoYdXWR9pcA5l0"},
	{"MD5 Default | Pwd: correct-ho...", "correct-horse-battery-staple", "$1$JZJlOObR", "$1$JZJlOObR$V5eZgkghINRGRiaD8DHiT."},
	{"MD5 Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$1$smETcPfw", "$1$smETcPfw$eLJXLewlk8rHO1qdTbTEk/"},
	{"MD5 Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$1$svdW7iI8", "$1$svdW7iI8$olpPpXutsh.qppfcLO5hl0"},
	{"Bcrypt Default | Pwd: password...", "password", "$2b$05$x0keT8UWO5TdIdMFxcB0BO", "$2b$05$x0keT8UWO5TdIdMFxcB0BOd8xhq3NtX2q3S1czRh4HhpSQA554xzq"},
	{"Bcrypt Default | Pwd: ...", "", "$2b$05$Woe/IMaWgjLbtJxboOWq4u", "$2b$05$Woe/IMaWgjLbtJxboOWq4uL77IMiFHv/GOtAlp75dIPia12ZGZsNq"},
	{"Bcrypt Default | Pwd: correct-ho...", "correct-horse-battery-staple", "$2b$05$3n1b34bdQXGUdUfq1Vu6TO", "$2b$05$3n1b34bdQXGUdUfq1Vu6TO/Sz9iSVl14qnx7wntgh.cVK7u0bPc2m"},
	{"Bcrypt Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$2b$05$g1vgLFJQ742u3y3bRczXb.", "$2b$05$g1vgLFJQ742u3y3bRczXb.uv/unR2P8yoeRQn8NoQlnsqLyPEz55a"},
	{"Bcrypt Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$2b$05$VxMfNgWUoixam53Hnc.ZY.", "$2b$05$VxMfNgWUoixam53Hnc.ZY.n9Rvpks5v2oT8/ZzaA7Ksf0B1Q0RBOG"},
	{"Bcrypt Min Cost (4) | Pwd: password...", "password", "$2b$05$GXQd8gqwvhmPae3LEqrKiO", "$2b$05$GXQd8gqwvhmPae3LEqrKiO4q7ilFoLtl7ni36wBXks6/p58bhH1FO"},
	{"Bcrypt Min Cost (4) | Pwd: ...", "", "$2b$05$1wBaJ.TVpBxPEXJEBBax9.", "$2b$05$1wBaJ.TVpBxPEXJEBBax9.2NR4/nMXNntMEPRWVu45YomLx0L2DKO"},
	{"Bcrypt Min Cost (4) | Pwd: correct-ho...", "correct-horse-battery-staple", "$2b$05$3ts1KBODBjunD9yqg3eBK.", "$2b$05$3ts1KBODBjunD9yqg3eBK.pIaN8dnCf6B1ak788emdv6No3msrM7y"},
	{"Bcrypt Min Cost (4) | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$2b$05$sitNn3aKHs0O4eYt4ivSIe", "$2b$05$sitNn3aKHs0O4eYt4ivSIeRG0A4vDk5AO9mKEeqe2B7He8ILMqlua"},
	{"Bcrypt Min Cost (4) | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$2b$05$lN9lr.6K.d0dY4Dp7uDY0u", "$2b$05$lN9lr.6K.d0dY4Dp7uDY0uyW9rukDI7PXLvAqguQ7gdehHSACO7im"},
	{"Bcrypt Cost (10) | Pwd: password...", "password", "$2b$10$yuLxlkxshQyW7/PFx9syJu", "$2b$10$yuLxlkxshQyW7/PFx9syJuJ6B5HupNUv0NveV4vMCJjDaR.v8HbHa"},
	{"Bcrypt Cost (10) | Pwd: ...", "", "$2b$10$kbWQWqxSoDfFMwbIO0bBHeQrhdJWILtde", "$2b$10$kbWQWqxSoDfFMwbIO0bBHeQrhdJWILtde.PN7Sz71G8CGgQfH3DoS"},
	{"Bcrypt Cost (10) | Pwd: correct-ho...", "correct-horse-battery-staple", "$2b$10$/wWxFBx2I/VBKxoSrf7y4Os", "$2b$10$/wWxFBx2I/VBKxoSrf7y4OsRNRmQ70AcWrUU81bYFRELDairR7sAa"},
	{"Bcrypt Cost (10) | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$2b$10$URMbVopBzKAUNJwzF4yGmu", "$2b$10$URMbVopBzKAUNJwzF4yGmu4BN8XREwnm02BAOzEdwDv69qve2Jjpe"},
	{"Bcrypt Cost (10) | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$2b$10$1/SFwjMRzW8EM9oO/UPsQO", "$2b$10$1/SFwjMRzW8EM9oO/UPsQOWDULdX22vM56Y/r4kNxUGwDaKkFyokW"},
	{"Yescrypt Default | Pwd: password...", "password", "$y$j9T$VsDvh.uipgs8K4FV6NXAZ1", "$y$j9T$VsDvh.uipgs8K4FV6NXAZ1$Xa6i7.vWDDEgl8ZehE/yJtAP3koxVDzHU9/EL.Borz7"},
	{"Yescrypt Default | Pwd: ...", "", "$y$j9T$I7TbuN9yIFTWmLoFbrfoP/", "$y$j9T$I7TbuN9yIFTWmLoFbrfoP/$3F5LowIXGFNKh8JIO0scirspfmxJdH2h8Rr2rQTPL10"},
	{"Yescrypt Default | Pwd: correct-ho...", "correct-horse-battery-staple", "$y$j9T$w895FVjOan4bAU07H4dgp/", "$y$j9T$w895FVjOan4bAU07H4dgp/$DDyIjEYc5sTBvNnin4pCAlwL1TqxFEt500F8A0ye088"},
	{"Yescrypt Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$y$j9T$xUhUzH2yqbc8Xm27GgFUN/", "$y$j9T$xUhUzH2yqbc8Xm27GgFUN/$WLEuBZmKaUgGX8Qmb89m3KXeM80NutSL75hkQEM6cm5"},
	{"Yescrypt Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$y$j9T$PE0uLnHcVlZRRfRezckVq.", "$y$j9T$PE0uLnHcVlZRRfRezckVq.$Gq34fHk6upiAgcUw.ykUa4LXO1/QgYihRXll519tS62"},
	{"Yescrypt Cost 10 | Pwd: password...", "password", "$y$jET$9CQQm4E0vj7ufl6ynL79b0", "$y$jET$9CQQm4E0vj7ufl6ynL79b0$gvVLl0ME2Rfh2C2.sLmtTS9sjZLIiEnK8MLVF7NPzHC"},
	{"Yescrypt Cost 10 | Pwd: ...", "", "$y$jET$xnTi1es/yN0T4HeI7tKrM/", "$y$jET$xnTi1es/yN0T4HeI7tKrM/$S.VxgN9mxe4H8Q.QBeLkKjcD3tGKMJ9DDCq73e2SRJ8"},
	{"Yescrypt Cost 10 | Pwd: correct-ho...", "correct-horse-battery-staple", "$y$jET$m3gIcvEKDF3IvsYJDZDAL1", "$y$jET$m3gIcvEKDF3IvsYJDZDAL1$TlfmvkgTuwTnxqd5z9QBcI5V2sQAa0.Rx8yqOTMVzM4"},
	{"Yescrypt Cost 10 | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "$y$jET$coM8BA6krp7v8JUIc22Qd1", "$y$jET$coM8BA6krp7v8JUIc22Qd1$TVjKI4u2p9f495hLgTafBAZn8s/Hr.llhl/mm0Hl72."},
	{"Yescrypt Cost 10 | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "$y$jET$LgnUPjM/DdTP.0.W1DjZY/", "$y$jET$LgnUPjM/DdTP.0.W1DjZY/$vwSce8rPpKtpftNiHE5vZ7lNwQgxOGPouGTuwcIQuf1"},
	{"DES Default | Pwd: password...", "password", "3o", "3orMDy42Bd9OM"},
	{"DES Default | Pwd: ...", "", "f2", "f2AzljVJSKjsw"},
	{"DES Default | Pwd: correct-ho...", "correct-horse-battery-staple", "nQ", "nQbOAE9UgOwRQ"},
	{"DES Default | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "2k", "2kxpJW996MhoQ"},
	{"DES Default | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "SM", "SMeglZ3bVSzzg"},
	{"DES Explicit Salt | Pwd: password...", "password", "xy", "xyAjYtmfRYx/."},
	{"DES Explicit Salt | Pwd: ...", "", "xy", "xyw1.V0rbu5mQ"},
	{"DES Explicit Salt | Pwd: correct-ho...", "correct-horse-battery-staple", "xy", "xyssDEVrYs7DU"},
	{"DES Explicit Salt | Pwd: €uro_Symb0...", "€uro_Symb0l_&_Unicod3", "xy", "xyAKMJas9Q9K6"},
	{"DES Explicit Salt | Pwd:  !\"#$%&'(...", " !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}~", "xy", "xyt39ciOTnr8g"},
}

func TestCryptCompatibility(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.Desc, func(t *testing.T) {
			// When the existing hash is passed as the 'salt' argument,
			// crypt(3) extracts the settings (method, rounds, salt)
			// and re-hashes the password to verify a match.
			got, err := cryptWrapper(tc.Password, tc.Salt)

			if err != nil {
				t.Fatalf("Crypt execution failed: %v", err)
			}

			if got != tc.Hash {
				t.Errorf("\nFAIL: %s\nInput:    %s\nExpected: %s\nGot:      %s",
					tc.Desc, tc.Password, tc.Hash, got)
			}
		})
	}
}
