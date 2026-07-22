package relay

import (
	"net/netip"
	"testing"
)

func TestIsULAAndIsGlobalUnicast(t *testing.T) {
	cases := []struct {
		addr       string
		wantULA    bool
		wantGlobal bool
	}{
		{"fc00::1", true, false},
		{"fd12:3456:789a::1", true, false},
		{"2001:db8::1", false, true},
		{"fe80::1", false, false},
		{"ff02::1", false, false},
		{"::1", false, false},
	}

	for _, c := range cases {
		addr := mustParseAddr(c.addr)
		if got := isULA(addr); got != c.wantULA {
			t.Errorf("isULA(%s) = %v, want %v", c.addr, got, c.wantULA)
		}
		if got := isGlobalUnicast(addr); got != c.wantGlobal {
			t.Errorf("isGlobalUnicast(%s) = %v, want %v", c.addr, got, c.wantGlobal)
		}
	}
}

// withCleanPrefixWatchState resets the package-level state evaluateWANPrefixes/
// startPrefixDeprecationWatch touch, and restores it after the test.
func withCleanPrefixWatchState(t *testing.T) {
	t.Helper()

	oldInterfaces := interfaces
	oldWatches := activePrefixWatches
	oldEnabled := prefixDeprecationEnabled

	interfaces = map[string]*Interface{}
	activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}
	prefixDeprecationEnabled = true

	t.Cleanup(func() {
		interfaces = oldInterfaces
		activePrefixWatches = oldWatches
		prefixDeprecationEnabled = oldEnabled
	})
}

func TestEvaluateWANPrefixesSeedsSilentlyOnFirstCall(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true, Addr6: []IPAddr{
		{Addr: mustParseAddr("2001:db8:1::1"), PrefixLen: 64, PreferredLT: 0, ValidLT: 0},
	}}
	interfaces["wan"] = wan

	evaluateWANPrefixes(wan)

	wantPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	if !wan.knownWANPrefixes[wantPrefix] {
		t.Fatalf("knownWANPrefixes = %v, want %s present", wan.knownWANPrefixes, wantPrefix)
	}
	if len(activePrefixWatches) != 0 {
		t.Fatalf("first (seeding) evaluation must not start any deprecation watch, got %v", activePrefixWatches)
	}
}

func TestEvaluateWANPrefixesDetectsSupersededPrefix(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true, Addr6: []IPAddr{
		{Addr: mustParseAddr("2001:db8:1::1"), PrefixLen: 64, PreferredLT: 0, ValidLT: 0},
	}}
	interfaces["wan"] = wan

	// First call just seeds.
	evaluateWANPrefixes(wan)

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	now := uint32(nowMono())
	wan.Addr6 = []IPAddr{
		// Old prefix's address is still present (kernel hasn't reaped it
		// yet) but its preferred lifetime is now finite/decaying...
		{Addr: mustParseAddr("2001:db8:1::1"), PrefixLen: 64, PreferredLT: now + 100, ValidLT: now + 3600},
		// ...while the new prefix's address has an infinite preferred
		// lifetime, so it wins as "current".
		{Addr: mustParseAddr("2001:db8:2::1"), PrefixLen: 64, PreferredLT: 0, ValidLT: 0},
	}

	evaluateWANPrefixes(wan)

	if wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("superseded prefix %s should have been dropped from knownWANPrefixes", oldPrefix)
	}
	if !wan.knownWANPrefixes[newPrefix] {
		t.Fatalf("fresher prefix %s should be recorded as known", newPrefix)
	}
}

func TestEvaluateWANPrefixesIgnoresEmptyAddressList(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true, Addr6: []IPAddr{
		{Addr: mustParseAddr("2001:db8:1::1"), PrefixLen: 64, PreferredLT: 0, ValidLT: 0},
	}}
	interfaces["wan"] = wan

	evaluateWANPrefixes(wan)
	wantPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	if !wan.knownWANPrefixes[wantPrefix] {
		t.Fatalf("expected %s to be seeded", wantPrefix)
	}

	// A transient gap (e.g. addresses momentarily unreadable) must not wipe
	// out already-known state.
	wan.Addr6 = nil
	evaluateWANPrefixes(wan)

	if !wan.knownWANPrefixes[wantPrefix] {
		t.Fatalf("transient empty address list should not clear knownWANPrefixes, got %v", wan.knownWANPrefixes)
	}
}
