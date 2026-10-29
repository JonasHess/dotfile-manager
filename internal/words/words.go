// Package words generates memorable passphrases from the EFF short
// wordlist (1296 words, about 10.3 bits per word).
package words

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"strings"
)

//go:embed eff_short.txt
var raw string

var list = strings.Fields(raw)

// Passphrase returns n random words joined by dashes.
func Passphrase(n int) string {
	out := make([]string, n)
	for i := range out {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
		out[i] = list[idx.Int64()]
	}
	return strings.Join(out, "-")
}

// Count is the wordlist size, for entropy statements.
func Count() int { return len(list) }
