package dnswire

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// NewA builds an A (or AAAA, for an IPv6 address) record.
func NewA(name string, ttl uint32, a netip.Addr) RR {
	if a.Is4() {
		b := a.As4()
		return RR{Name: name, Type: TypeA, Class: ClassINET, TTL: ttl, Data: b[:]}
	}
	b := a.As16()
	return RR{Name: name, Type: TypeAAAA, Class: ClassINET, TTL: ttl, Data: b[:]}
}

// NewName builds an RR whose RDATA is a single name (NS, CNAME, PTR).
func NewName(name string, typ uint16, ttl uint32, target string) RR {
	d, err := appendName(nil, target, nil)
	if err != nil {
		panic(fmt.Sprintf("dnswire: bad target %q: %v", target, err))
	}
	return RR{Name: name, Type: typ, Class: ClassINET, TTL: ttl, Data: d}
}

// NewSOA builds an SOA record. minimum is the negative-caching TTL (RFC 2308).
func NewSOA(zone string, ttl uint32, mname, rname string, serial, minimum uint32) RR {
	d, _ := appendName(nil, mname, nil)
	d, _ = appendName(d, rname, nil)
	for _, v := range []uint32{serial, 7200, 3600, 1209600, minimum} {
		d = binary.BigEndian.AppendUint32(d, v)
	}
	return RR{Name: zone, Type: TypeSOA, Class: ClassINET, TTL: ttl, Data: d}
}

// NewTXT builds a TXT record, splitting text into 255-byte strings.
func NewTXT(name string, ttl uint32, text string) RR {
	var d []byte
	for len(text) > 0 {
		n := min(len(text), 255)
		d = append(d, byte(n))
		d = append(d, text[:n]...)
		text = text[n:]
	}
	return RR{Name: name, Type: TypeTXT, Class: ClassINET, TTL: ttl, Data: d}
}

// Addr returns the address of an A or AAAA record.
func (rr RR) Addr() (netip.Addr, bool) {
	switch {
	case rr.Type == TypeA && len(rr.Data) == 4:
		return netip.AddrFrom4([4]byte(rr.Data)), true
	case rr.Type == TypeAAAA && len(rr.Data) == 16:
		return netip.AddrFrom16([16]byte(rr.Data)), true
	}
	return netip.Addr{}, false
}

// Target returns the name in an NS, CNAME or PTR record.
func (rr RR) Target() (string, bool) {
	if rr.Type != TypeNS && rr.Type != TypeCNAME && rr.Type != TypePTR {
		return "", false
	}
	n, _, err := readName(rr.Data, 0)
	return n, err == nil
}

// SOANegTTL returns the negative-caching TTL of an SOA record:
// min(SOA TTL, SOA MINIMUM), as RFC 2308 section 5 specifies.
func (rr RR) SOANegTTL() (uint32, bool) {
	if rr.Type != TypeSOA || len(rr.Data) < 20 {
		return 0, false
	}
	minimum := binary.BigEndian.Uint32(rr.Data[len(rr.Data)-4:])
	return min(minimum, rr.TTL), true
}

// TypeString names a type for logs.
func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeANY:
		return "ANY"
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType is the inverse of TypeString for the common types.
func ParseType(s string) (uint16, bool) {
	s = strings.ToUpper(s)
	for _, t := range []uint16{TypeA, TypeNS, TypeCNAME, TypeSOA, TypePTR, TypeMX, TypeTXT, TypeAAAA, TypeSRV, TypeANY} {
		if TypeString(t) == s {
			return t, true
		}
	}
	return 0, false
}

// RcodeString names a response code.
func RcodeString(r uint8) string {
	switch r {
	case RcodeSuccess:
		return "NOERROR"
	case RcodeFormErr:
		return "FORMERR"
	case RcodeServFail:
		return "SERVFAIL"
	case RcodeNXDomain:
		return "NXDOMAIN"
	case RcodeNotImp:
		return "NOTIMP"
	case RcodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func (rr RR) String() string {
	var v string
	if a, ok := rr.Addr(); ok {
		v = a.String()
	} else if t, ok := rr.Target(); ok {
		v = t
	} else {
		v = fmt.Sprintf("\\# %d %x", len(rr.Data), rr.Data)
	}
	return fmt.Sprintf("%s %d %s %s", rr.Name, rr.TTL, TypeString(rr.Type), v)
}
