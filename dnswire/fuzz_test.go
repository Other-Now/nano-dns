package dnswire

import (
	"reflect"
	"testing"
)

// FuzzUnpack: any byte string must either be rejected or survive
// Unpack -> Pack -> Unpack unchanged. Panics, hangs and silent changes are
// all failures.
func FuzzUnpack(f *testing.F) {
	b, _ := sampleMsg().Pack()
	f.Add(b)
	q := &Msg{ID: 7, RecursionDesired: true, Question: []Question{{Name: "example.org.", Type: TypeAAAA, Class: ClassINET}}}
	b, _ = q.Pack()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var m Msg
		if err := m.Unpack(data); err != nil {
			return
		}
		packed, err := m.Pack()
		if err != nil {
			// Unpack accepted it, so it must be packable again.
			t.Fatalf("pack after unpack: %v\nmsg %+v", err, m)
		}
		var m2 Msg
		if err := m2.Unpack(packed); err != nil {
			t.Fatalf("re-unpack: %v", err)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("round trip changed message\n 1: %+v\n 2: %+v", m, m2)
		}
	})
}
