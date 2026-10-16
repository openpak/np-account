package nettest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// updateList answers the firmware's system update check (feu01.ps3.update,
// /update/ps3/list/<region>/ps3-updatelist.txt). VSH needs Dest, ImageVersion,
// SystemSoftwareVersion, CDN and CDN_Timeout per line, a Content-Length (no
// chunking) and less than 64 KiB. An ImageVersion not above the installed one
// reads as "already latest"; Dest is the console's target id, so every value
// is listed.
func updateList(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("# OpenPak PS3 update list\n")
	tail := ";ImageVersion=00000001;SystemSoftwareVersion=4.93;CDN=http://" + r.Host + "/update/ps3/image/;CDN_Timeout=30\n"
	for d := 0; d < 100; d++ {
		fmt.Fprintf(&b, "Dest=%02d%s", d, tail)
	}
	for d := 0; d < 256; d++ {
		fmt.Fprintf(&b, "Dest=%02x%s", d, tail)
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(b.Len()))
	w.Write([]byte(b.String()))
}
