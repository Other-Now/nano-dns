// Package dnswire encodes and decodes DNS messages (RFC 1035) by hand.
//
// Design choices, kept deliberately simple:
//   - Names are held in presentation form, lower-cased, with a trailing dot
//     ("www.example.com."). The root is ".".
//   - RR data is kept as raw wire bytes. Names inside RDATA (NS, CNAME, PTR,
//     MX, SOA, SRV) are *decompressed* on parse, because a compression pointer
//     only means something inside the message it came from. On pack, names in
//     the well-known types are compressed again.
//   - Compression pointers must point strictly backwards. That alone makes
//     pointer loops impossible.
package dnswire

import (
	"encoding/binary"
	"errors"
)

// RR types and classes used by the resolver.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeANY   uint16 = 255

	ClassINET uint16 = 1
)

// Response codes.
const (
	RcodeSuccess  uint8 = 0
	RcodeFormErr  uint8 = 1
	RcodeServFail uint8 = 2
	RcodeNXDomain uint8 = 3
	RcodeNotImp   uint8 = 4
	RcodeRefused  uint8 = 5
)

var (
	ErrShort      = errors.New("dnswire: message too short")
	ErrPointer    = errors.New("dnswire: bad compression pointer")
	ErrLabel      = errors.New("dnswire: bad label")
	ErrNameLen    = errors.New("dnswire: name longer than 255 octets")
	ErrRDataLen   = errors.New("dnswire: rdata length mismatch")
	ErrTooBig     = errors.New("dnswire: message longer than 65535 octets")
	ErrEmptyLabel = errors.New("dnswire: empty label")
)

// Question is one entry of the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is a resource record. Data is the uncompressed RDATA.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// Msg is a whole DNS message.
type Msg struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticData      bool
	CheckingDisabled   bool
	Rcode              uint8

	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
}

const headerLen = 12

func (m *Msg) flags() uint16 {
	var f uint16
	if m.Response {
		f |= 1 << 15
	}
	f |= uint16(m.Opcode&0xF) << 11
	if m.Authoritative {
		f |= 1 << 10
	}
	if m.Truncated {
		f |= 1 << 9
	}
	if m.RecursionDesired {
		f |= 1 << 8
	}
	if m.RecursionAvailable {
		f |= 1 << 7
	}
	if m.AuthenticData {
		f |= 1 << 5
	}
	if m.CheckingDisabled {
		f |= 1 << 4
	}
	f |= uint16(m.Rcode & 0xF)
	return f
}

func (m *Msg) setFlags(f uint16) {
	m.Response = f&(1<<15) != 0
	m.Opcode = uint8(f>>11) & 0xF
	m.Authoritative = f&(1<<10) != 0
	m.Truncated = f&(1<<9) != 0
	m.RecursionDesired = f&(1<<8) != 0
	m.RecursionAvailable = f&(1<<7) != 0
	m.AuthenticData = f&(1<<5) != 0
	m.CheckingDisabled = f&(1<<4) != 0
	m.Rcode = uint8(f & 0xF)
}

// Unpack parses a wire-format message into m.
func (m *Msg) Unpack(b []byte) error {
	*m = Msg{}
	if len(b) < headerLen {
		return ErrShort
	}
	m.ID = binary.BigEndian.Uint16(b[0:])
	m.setFlags(binary.BigEndian.Uint16(b[2:]))
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))
	off := headerLen
	for i := 0; i < qd; i++ {
		name, next, err := readName(b, off)
		if err != nil {
			return err
		}
		if next+4 > len(b) {
			return ErrShort
		}
		m.Question = append(m.Question, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[next:]),
			Class: binary.BigEndian.Uint16(b[next+2:]),
		})
		off = next + 4
	}
	var err error
	if m.Answer, off, err = readRRs(b, off, an); err != nil {
		return err
	}
	if m.Authority, off, err = readRRs(b, off, ns); err != nil {
		return err
	}
	if m.Additional, _, err = readRRs(b, off, ar); err != nil {
		return err
	}
	return nil
}

func readRRs(b []byte, off, n int) ([]RR, int, error) {
	if n == 0 {
		return nil, off, nil
	}
	var rrs []RR
	for i := 0; i < n; i++ {
		rr, next, err := readRR(b, off)
		if err != nil {
			return nil, off, err
		}
		rrs = append(rrs, rr)
		off = next
	}
	return rrs, off, nil
}

func readRR(b []byte, off int) (RR, int, error) {
	name, next, err := readName(b, off)
	if err != nil {
		return RR{}, 0, err
	}
	if next+10 > len(b) {
		return RR{}, 0, ErrShort
	}
	rr := RR{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[next:]),
		Class: binary.BigEndian.Uint16(b[next+2:]),
		TTL:   binary.BigEndian.Uint32(b[next+4:]),
	}
	rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
	start := next + 10
	end := start + rdlen
	if end > len(b) {
		return RR{}, 0, ErrShort
	}
	rr.Data, err = readRData(b, start, end, rr.Type)
	if err != nil {
		return RR{}, 0, err
	}
	return rr, end, nil
}

// readRData copies RDATA, expanding compressed names for the types that may
// carry them.
func readRData(b []byte, start, end int, typ uint16) ([]byte, error) {
	// fixed prefix bytes before the name(s), and how many names follow
	var prefix, names, suffix int
	switch typ {
	case TypeNS, TypeCNAME, TypePTR:
		names = 1
	case TypeMX:
		prefix, names = 2, 1
	case TypeSRV:
		prefix, names = 6, 1
	case TypeSOA:
		names, suffix = 2, 20
	default:
		return append([]byte(nil), b[start:end]...), nil
	}
	if start+prefix > end {
		return nil, ErrRDataLen
	}
	out := append([]byte(nil), b[start:start+prefix]...)
	off := start + prefix
	for i := 0; i < names; i++ {
		// Read against the whole message (pointers are message-relative),
		// but the name must start inside this RDATA.
		if off >= end {
			return nil, ErrRDataLen
		}
		name, next, err := readName(b[:end], off)
		if err != nil {
			return nil, err
		}
		if out, err = appendName(out, name, nil); err != nil {
			return nil, err
		}
		off = next
	}
	if off+suffix != end {
		return nil, ErrRDataLen
	}
	return append(out, b[off:end]...), nil
}

// Pack encodes m into wire format with name compression.
func (m *Msg) Pack() ([]byte, error) {
	buf := make([]byte, headerLen, 512)
	binary.BigEndian.PutUint16(buf[0:], m.ID)
	binary.BigEndian.PutUint16(buf[2:], m.flags())
	counts := []int{len(m.Question), len(m.Answer), len(m.Authority), len(m.Additional)}
	for i, c := range counts {
		if c > 0xFFFF {
			return nil, ErrTooBig
		}
		binary.BigEndian.PutUint16(buf[4+2*i:], uint16(c))
	}
	comp := map[string]int{}
	var err error
	for _, q := range m.Question {
		if buf, err = appendName(buf, q.Name, comp); err != nil {
			return nil, err
		}
		buf = binary.BigEndian.AppendUint16(buf, q.Type)
		buf = binary.BigEndian.AppendUint16(buf, q.Class)
	}
	for _, sec := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for i := range sec {
			if buf, err = appendRR(buf, &sec[i], comp); err != nil {
				return nil, err
			}
		}
	}
	if len(buf) > 0xFFFF {
		return nil, ErrTooBig
	}
	return buf, nil
}

func appendRR(buf []byte, rr *RR, comp map[string]int) ([]byte, error) {
	var err error
	if buf, err = appendName(buf, rr.Name, comp); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, rr.Type)
	buf = binary.BigEndian.AppendUint16(buf, rr.Class)
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	lenAt := len(buf)
	buf = append(buf, 0, 0)
	if buf, err = appendRData(buf, rr, comp); err != nil {
		return nil, err
	}
	rdlen := len(buf) - lenAt - 2
	if rdlen > 0xFFFF {
		return nil, ErrTooBig
	}
	binary.BigEndian.PutUint16(buf[lenAt:], uint16(rdlen))
	return buf, nil
}

// appendRData re-compresses names in the RFC 1035 types (NS, CNAME, PTR, MX,
// SOA). RFC 3597 forbids compressing names in newer types, so SRV and
// everything else is copied verbatim.
func appendRData(buf []byte, rr *RR, comp map[string]int) ([]byte, error) {
	var prefix, names int
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR:
		names = 1
	case TypeMX:
		prefix, names = 2, 1
	case TypeSOA:
		names = 2
	default:
		return append(buf, rr.Data...), nil
	}
	d := rr.Data
	if len(d) < prefix {
		return nil, ErrRDataLen
	}
	buf = append(buf, d[:prefix]...)
	off := prefix
	for i := 0; i < names; i++ {
		name, next, err := readName(d, off)
		if err != nil {
			return nil, err
		}
		if buf, err = appendName(buf, name, comp); err != nil {
			return nil, err
		}
		off = next
	}
	return append(buf, d[off:]...), nil
}

// EDNS returns the advertised UDP payload size if the message has an OPT RR.
func (m *Msg) EDNS() (uint16, bool) {
	for _, rr := range m.Additional {
		if rr.Type == TypeOPT {
			return rr.Class, true
		}
	}
	return 0, false
}

// SetEDNS adds an OPT RR (RFC 6891) advertising size, replacing any existing one.
func (m *Msg) SetEDNS(size uint16) {
	out := m.Additional[:0]
	for _, rr := range m.Additional {
		if rr.Type != TypeOPT {
			out = append(out, rr)
		}
	}
	m.Additional = append(out, RR{Name: ".", Type: TypeOPT, Class: size})
}

// PackLimit packs m; if the result is longer than limit it sets TC, drops
// the record sections (keeping OPT) and packs again. That is what a UDP
// responder must do (RFC 1035 4.2.1, RFC 6891 7).
func (m *Msg) PackLimit(limit int) ([]byte, error) {
	b, err := m.Pack()
	if err != nil || len(b) <= limit {
		return b, err
	}
	t := *m
	t.Truncated = true
	t.Answer, t.Authority = nil, nil
	t.Additional = nil
	for _, rr := range m.Additional {
		if rr.Type == TypeOPT {
			t.Additional = append(t.Additional, rr)
		}
	}
	return t.Pack()
}
