package dnswire

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func sampleMsg() *Msg {
	m := &Msg{ID: 0xBEEF, Response: true, RecursionDesired: true, RecursionAvailable: true}
	m.Question = []Question{{Name: "www.example.com.", Type: TypeA, Class: ClassINET}}
	m.Answer = []RR{
		NewName("www.example.com.", TypeCNAME, 300, "edge.example.com."),
		NewA("edge.example.com.", 60, netip.MustParseAddr("192.0.2.7")),
	}
	m.Authority = []RR{
		NewName("example.com.", TypeNS, 3600, "ns1.example.com."),
		NewSOA("example.com.", 3600, "ns1.example.com.", "hostmaster.example.com.", 1, 300),
	}
	m.Additional = []RR{NewA("ns1.example.com.", 3600, netip.MustParseAddr("192.0.2.53"))}
	m.SetEDNS(1232)
	return m
}

func TestRoundTrip(t *testing.T) {
	m := sampleMsg()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var got Msg
	if err := got.Unpack(b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&got, m) {
		t.Fatalf("round trip mismatch\n got %+v\nwant %+v", got, *m)
	}
}

func TestCompressionShrinks(t *testing.T) {
	m := sampleMsg()
	b, _ := m.Pack()
	// Without compression every "example.com." costs 13 bytes. There are 9
	// occurrences (owners + rdata), so the packed message must be far smaller
	// than a naive encoding.
	if len(b) > 200 {
		t.Fatalf("packed %d bytes, compression not working", len(b))
	}
	if !bytes.Contains(b, []byte{0xC0, 12}) {
		t.Fatal("no pointer to the question name")
	}
}

func TestPointerLoopRejected(t *testing.T) {
	// header with qdcount=1, then a name that is a pointer to itself
	b, _ := hex.DecodeString("000001000001000000000000" + "c00c" + "00010001")
	var m Msg
	if err := m.Unpack(b); err != ErrPointer {
		t.Fatalf("want ErrPointer, got %v", err)
	}
	// forward pointer
	b, _ = hex.DecodeString("000001000001000000000000" + "c00e" + "00" + "00010001")
	if err := m.Unpack(b); err != ErrPointer {
		t.Fatalf("forward pointer: want ErrPointer, got %v", err)
	}
}

func TestNameTooLong(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 63)+".", 4) // 4*64+1 = 257 wire bytes
	if _, err := appendName(nil, long, nil); err != ErrNameLen {
		t.Fatalf("want ErrNameLen, got %v", err)
	}
	ok := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61) + "." // 255
	if _, err := appendName(nil, ok, nil); err != nil {
		t.Fatalf("255-octet name rejected: %v", err)
	}
}

func TestEscapesRoundTrip(t *testing.T) {
	// a label containing a dot, a backslash, a space and a 0xFF byte
	wire := []byte{6, 'a', '.', '\\', ' ', 0xFF, 'Z', 3, 'c', 'o', 'm', 0}
	name, _, err := readName(wire, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != `a\.\\\032\255z.com.` {
		t.Fatalf("presentation %q", name)
	}
	back, err := appendName(nil, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), wire...)
	want[6] = 'z' // lower-cased on read
	if !bytes.Equal(back, want) {
		t.Fatalf("wire %x want %x", back, want)
	}
}

func TestPackLimitTruncates(t *testing.T) {
	m := &Msg{ID: 1, Response: true}
	m.Question = []Question{{Name: "big.example.", Type: TypeTXT, Class: ClassINET}}
	m.Answer = []RR{NewTXT("big.example.", 60, strings.Repeat("x", 2000))}
	m.SetEDNS(1232)
	b, err := m.PackLimit(512)
	if err != nil {
		t.Fatal(err)
	}
	var got Msg
	if err := got.Unpack(b); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(got.Answer) != 0 || len(b) > 512 {
		t.Fatalf("not truncated properly: tc=%v an=%d len=%d", got.Truncated, len(got.Answer), len(b))
	}
	if _, ok := got.EDNS(); !ok {
		t.Fatal("OPT dropped on truncation")
	}
}

func TestNameHelpers(t *testing.T) {
	if !IsSubdomain("a.example.com.", "example.com.") || IsSubdomain("aexample.com.", "example.com.") {
		t.Fatal("IsSubdomain")
	}
	if Parent("www.example.com.") != "example.com." || Parent("com.") != "." {
		t.Fatal("Parent")
	}
	if ChildOf("a.b.example.com.", "com.") != "example.com." || ChildOf("example.com.", ".") != "com." {
		t.Fatal("ChildOf")
	}
	if Canonical("WWW.Example.COM") != "www.example.com." {
		t.Fatal("Canonical")
	}
}

func TestSOANegTTL(t *testing.T) {
	soa := NewSOA("example.com.", 900, "ns.", "h.", 1, 300)
	if v, _ := soa.SOANegTTL(); v != 300 {
		t.Fatalf("got %d want 300", v)
	}
	soa.TTL = 60
	if v, _ := soa.SOANegTTL(); v != 60 {
		t.Fatalf("got %d want 60 (min of TTL and MINIMUM)", v)
	}
}

// BenchmarkUnpackPack: parse a typical referral-sized response and pack it
// again (what the resolver does per upstream reply, and the server per
// client response).
func BenchmarkUnpackPack(b *testing.B) {
	wire, _ := sampleMsg().Pack()
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for i := 0; i < b.N; i++ {
		var m Msg
		if err := m.Unpack(wire); err != nil {
			b.Fatal(err)
		}
		if _, err := m.Pack(); err != nil {
			b.Fatal(err)
		}
	}
}
