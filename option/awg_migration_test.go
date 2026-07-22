package option

import (
	"context"
	"testing"
)

func TestAwgFlatToNestedMigration(t *testing.T) {
	ctx := context.Background()

	// Legacy flat schema (params at top level).
	flat := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"listen_port":10863,"jc":4,"jmin":8,"s1":15,"h1":"1234567890","i1":"abcd"}`
	var o AwgEndpointOptions
	if err := o.UnmarshalJSONContext(ctx, []byte(flat)); err != nil {
		t.Fatal(err)
	}
	if o.Awg.Jc != 4 || o.Awg.Jmin != 8 || o.Awg.S1 != 15 || o.Awg.H1 != "1234567890" || o.Awg.I1 != "abcd" {
		t.Fatalf("flat params not folded into Awg: %+v", o.Awg)
	}
	if o.ListenPort != 10863 {
		t.Fatalf("listen_port lost: %d", o.ListenPort)
	}

	// Nested schema keeps working.
	nested := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"awg":{"jc":7,"s2":20}}`
	var o2 AwgEndpointOptions
	if err := o2.UnmarshalJSONContext(ctx, []byte(nested)); err != nil {
		t.Fatal(err)
	}
	if o2.Awg.Jc != 7 || o2.Awg.S2 != 20 {
		t.Fatalf("nested schema broken: %+v", o2.Awg)
	}

	// When both present, nested wins (no accidental override from legacy flat).
	both := `{"private_key":"aGVsbG8=","address":["10.0.0.1/24"],"jc":1,"awg":{"jc":9}}`
	var o3 AwgEndpointOptions
	if err := o3.UnmarshalJSONContext(ctx, []byte(both)); err != nil {
		t.Fatal(err)
	}
	if o3.Awg.Jc != 9 {
		t.Fatalf("nested should take precedence, got Jc=%d", o3.Awg.Jc)
	}

	// Minimal prod-style config (no obfuscation) stays empty, no error.
	minimal := `{"tag":"awg-in","private_key":"aGVsbG8=","address":["10.0.0.1/24"],"listen_port":10863,"mtu":1280}`
	var o4 AwgEndpointOptions
	if err := o4.UnmarshalJSONContext(ctx, []byte(minimal)); err != nil {
		t.Fatal(err)
	}
	if o4.Awg.IsAvailble() {
		t.Fatalf("minimal config should have empty Awg, got %+v", o4.Awg)
	}
}
