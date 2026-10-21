package native

import (
	"encoding/hex"
	"testing"
)

// The firmware analysis produced this 248-byte reply for two countries; keep it byte-identical.
func TestCountriesMatchesAnalysisExample(t *testing.T) {
	got := hex.EncodeToString(Countries(DefaultCountries[:2]))
	want := "00000000000100f0005b0002005b0072757300000000010000000000010010005c0001005c0008656e0000000000000001004f009b0001009b0047656e00000000556e6974656420537461746573"
	if len(got) != 248*2 || got[:len(want)] != want {
		t.Fatalf("got %s", got)
	}
}
