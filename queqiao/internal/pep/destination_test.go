package pep

import (
	"context"
	"net"
	"testing"
)

func TestPublicDestinationIP(t *testing.T) {
	for _, test := range []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"169.254.169.254", false},
		{"192.0.2.1", false},
		{"192.88.99.2", false},
		{"2001:4860:4860::8888", true},
		{"::1", false},
		{"64:ff9b::a00:1", false},
		{"64:ff9b:1::a00:1", false},
		{"100::1", false},
		{"100:0:0:1::1", false},
		{"2001:2::1", false},
		{"2001:10::1", false},
		{"2001:db8::1", false},
		{"2002:a00:1::1", false},
		{"3fff::1", false},
		{"5f00::1", false},
	} {
		if got := publicDestinationIP(net.ParseIP(test.ip)); got != test.public {
			t.Errorf("publicDestinationIP(%s) = %v, want %v", test.ip, got, test.public)
		}
	}
}

// The UDP resolver applies the same public-address policy as TCP: a peer
// cannot reach a private destination either way.
func TestResolveUDPAddrUsesDestinationPolicy(t *testing.T) {
	addresses, err := (DestinationPolicy{}).ResolveUDPAddr(context.Background(), "8.8.8.8:53")
	if err != nil || len(addresses) != 1 || addresses[0].Port != 53 {
		t.Fatalf("public address = %v, %v", addresses, err)
	}
	if _, err = (DestinationPolicy{}).ResolveUDPAddr(context.Background(), "127.0.0.1:53"); err == nil {
		t.Fatal("private address was accepted")
	}
	if addresses, err = (DestinationPolicy{AllowPrivate: true}).ResolveUDPAddr(context.Background(), "127.0.0.1:53"); err != nil || len(addresses) != 1 {
		t.Fatalf("allowed private address = %v, %v", addresses, err)
	}
}
