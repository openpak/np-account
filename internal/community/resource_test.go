package community

import (
	"bytes"
	"testing"
)

func TestResourceWireFrame(t *testing.T) {
	// Independently computed HMAC-SHA1 vector over 11 XML bytes plus 53 zeros.
	want := "<!--Sce-Np-Signature: 0b7c4d7857929e218ddc749fcf95ac7597965a42-->\n<nptrophy/>"
	got := signedResource([]byte("<nptrophy/>"), bytes.Repeat([]byte("k"), 20))
	if string(got) != want {
		t.Fatalf("unexpected signature frame: %s", got)
	}
	if len(got)-len("<nptrophy/>") != 66 {
		t.Fatal("VSH consumes exactly 65 header bytes plus LF")
	}
}
