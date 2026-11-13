package dnswire

import (
	"strings"
)

const maxPointers = 64

// readName reads a possibly-compressed name starting at off. It returns the
// name in lower-case presentation form and the offset just past the name in
// the original (uncompressed) position.
func readName(msg []byte, off int) (string, int, error) {
	var sb []byte
	wire := 1 // the terminating root label
	next := -1
	ptrs := 0
	for {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if next < 0 {
					next = off + 1
				}
				if len(sb) == 0 {
					return ".", next, nil
				}
				return string(sb), next, nil
			}
			if off+1+c > len(msg) {
				return "", 0, ErrShort
			}
			wire += c + 1
			if wire > 255 {
				return "", 0, ErrNameLen
			}
			sb = appendLabel(sb, msg[off+1:off+1+c])
			sb = append(sb, '.')
			off += 1 + c
		case 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrShort
			}
			p := (c&0x3F)<<8 | int(msg[off+1])
			// Strictly backwards: every hop lowers off, so no loops.
			if p >= off {
				return "", 0, ErrPointer
			}
			if ptrs++; ptrs > maxPointers {
				return "", 0, ErrPointer
			}
			if next < 0 {
				next = off + 2
			}
			off = p
		default: // 0x40 / 0x80: extended label types, obsolete
			return "", 0, ErrLabel
		}
	}
}

// appendLabel writes one label in presentation form, lower-casing ASCII and
// escaping anything that would not survive a round trip.
func appendLabel(sb []byte, l []byte) []byte {
	for _, ch := range l {
		switch {
		case ch >= 'A' && ch <= 'Z':
			sb = append(sb, ch+('a'-'A'))
		case ch == '.' || ch == '\\':
			sb = append(sb, '\\', ch)
		case ch <= ' ' || ch >= 0x7F:
			sb = append(sb, '\\', '0'+ch/100, '0'+(ch/10)%10, '0'+ch%10)
		default:
			sb = append(sb, ch)
		}
	}
	return sb
}

// appendName encodes a presentation-form name. If comp is non-nil, suffixes
// already written are replaced by pointers and new ones are recorded.
func appendName(buf []byte, name string, comp map[string]int) ([]byte, error) {
	if name == "" || name == "." {
		return append(buf, 0), nil
	}
	// Walk labels; each iteration knows the remaining suffix name[i:].
	wire := 1
	i := 0
	for i < len(name) {
		suffix := name[i:]
		if suffix == "." {
			break
		}
		if comp != nil {
			if p, ok := comp[suffix]; ok {
				return append(buf, byte(0xC0|p>>8), byte(p)), nil
			}
			if len(buf) < 0x3FFF {
				comp[suffix] = len(buf)
			}
		}
		lenAt := len(buf)
		buf = append(buf, 0)
		n := 0
		for i < len(name) && name[i] != '.' {
			ch := name[i]
			if ch == '\\' {
				if i+1 >= len(name) {
					return nil, ErrLabel
				}
				if isDigit(name[i+1]) {
					// \DDD: exactly three decimal digits
					if i+3 >= len(name) || !isDigit(name[i+2]) || !isDigit(name[i+3]) {
						return nil, ErrLabel
					}
					v := int(name[i+1]-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
					if v > 255 {
						return nil, ErrLabel
					}
					ch = byte(v)
					i += 4
				} else {
					ch = name[i+1]
					i += 2
				}
			} else {
				i++
			}
			buf = append(buf, ch)
			n++
		}
		if n == 0 {
			return nil, ErrEmptyLabel
		}
		if n > 63 {
			return nil, ErrLabel
		}
		buf[lenAt] = byte(n)
		wire += n + 1
		if wire > 255 {
			return nil, ErrNameLen
		}
		i++ // skip the dot (or run off the end for a name with no trailing dot)
	}
	return append(buf, 0), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Canonical lower-cases a name and makes it fully qualified.
func Canonical(name string) string {
	name = strings.ToLower(name)
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// IsSubdomain reports whether child equals parent or is below it. Both must
// be canonical. (Escaped dots inside labels are not handled; they do not
// occur in the names this resolver deals with.)
func IsSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	if len(child) < len(parent) {
		return false
	}
	if len(child) == len(parent) {
		return child == parent
	}
	return child[len(child)-len(parent)-1] == '.' && child[len(child)-len(parent):] == parent
}

// Parent strips the first label: "www.example.com." -> "example.com.",
// "com." -> ".".
func Parent(name string) string {
	if name == "." {
		return "."
	}
	i := strings.IndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return "."
	}
	return name[i+1:]
}

// CountLabels returns the number of labels ("." has 0).
func CountLabels(name string) int {
	if name == "." {
		return 0
	}
	return strings.Count(name, ".")
}

// ChildOf returns the ancestor of name that has exactly one more label than
// zone. Used by QNAME minimisation: zone "com.", name "a.b.example.com." ->
// "example.com.". name must be below zone.
func ChildOf(name, zone string) string {
	want := CountLabels(zone) + 1
	n := name
	for CountLabels(n) > want {
		n = Parent(n)
	}
	return n
}
