package native

import "encoding/binary"

// Country is one entry of the getCountries reply.
type Country struct {
	Code      string // "us"
	Region    uint32 // 1 US, 2 EU, 3 Asia (inferred from the firmware's language table)
	Languages []string
	Names     map[string]string // language -> localized name
}

// DefaultCountries is what the lab serves until the real list is configured.
var DefaultCountries = []Country{
	{"us", 1, []string{"en"}, map[string]string{"en": "United States"}},
	{"gb", 2, []string{"en"}, map[string]string{"en": "United Kingdom"}},
}

// Countries encodes the getCountries reply: list 0x5b of countries, each with a list 0x5c of
// 8-byte language codes and a list 0x9b of (6-byte language, 65-byte name).
func Countries(cs []Country) []byte {
	var items [][]byte
	for _, c := range cs {
		v := append(fixed(c.Code, 3), make([]byte, 8)...)
		binary.BigEndian.PutUint32(v[3:], c.Region)
		var langs, names [][]byte
		for _, l := range c.Languages {
			langs = append(langs, Elem(0x5c, fixed(l, 8)))
			names = append(names, Elem(0x9b, append(fixed(l, 6), fixed(c.Names[l], 65)...)))
		}
		v = append(v, List(0x5c, langs...)...)
		v = append(v, List(0x9b, names...)...)
		items = append(items, Elem(0x5b, v))
	}
	return Reply(List(0x5b, items...))
}
