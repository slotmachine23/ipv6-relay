package relay

import (
	"encoding/binary"
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

// buildTestRA constructs a minimal Router Advertisement (16-byte fixed
// header, all zero except what's needed) carrying a single Prefix
// Information Option for prefix.
func buildTestRA(prefix netip.Prefix) []byte {
	pkt := make([]byte, 16+32)
	pkt[0] = ndRouterAdvert
	opt := pkt[16:]
	opt[0] = ndOptPrefixInfo
	opt[1] = 32 / 8
	opt[2] = uint8(prefix.Bits())
	binary.BigEndian.PutUint32(opt[4:8], 3600)
	binary.BigEndian.PutUint32(opt[8:12], 1800)
	copy(opt[16:32], prefix.Addr().AsSlice())
	return pkt
}

func TestParsePIOPrefixesFiltersToULAAndGlobalUnicast(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"2001:db8:1::/64", true},
		{"fd00:1::/64", true},
		{"fe80::/64", false},
	}

	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		got := parsePIOPrefixes(buildTestRA(p))
		if c.want && (len(got) != 1 || got[0] != p.Masked()) {
			t.Errorf("parsePIOPrefixes(%s) = %v, want [%s]", c.prefix, got, p.Masked())
		}
		if !c.want && len(got) != 0 {
			t.Errorf("parsePIOPrefixes(%s) = %v, want empty", c.prefix, got)
		}
	}
}

// withCleanPrefixWatchState resets the package-level state
// trackWANPrefixSnooping/startPrefixDeprecationWatch touch, and restores it
// after the test.
func withCleanPrefixWatchState(t *testing.T) {
	t.Helper()

	oldInterfaces := interfaces
	oldWatches := activePrefixWatches
	oldEnabled := prefixDeprecationEnabled
	oldThreshold := prefixMismatchThreshold

	interfaces = map[string]*Interface{}
	activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}
	prefixDeprecationEnabled = true
	prefixMismatchThreshold = 3

	t.Cleanup(func() {
		interfaces = oldInterfaces
		activePrefixWatches = oldWatches
		prefixDeprecationEnabled = oldEnabled
		prefixMismatchThreshold = oldThreshold
	})
}

func TestTrackWANPrefixSnoopingSeedsSilentlyOnFirstRA(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	want := netip.MustParsePrefix("2001:db8:1::/64")
	trackWANPrefixSnooping(wan, buildTestRA(want))

	if wan.currentWANPrefix != want {
		t.Fatalf("currentWANPrefix = %v, want %v", wan.currentWANPrefix, want)
	}
	if len(activePrefixWatches) != 0 {
		t.Fatalf("first (seeding) RA must not start any deprecation watch, got %v", activePrefixWatches)
	}
}

func TestTrackWANPrefixSnoopingRequiresThresholdMismatches(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	// Below-threshold mismatches must not switch currentWANPrefix yet.
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	if wan.currentWANPrefix != oldPrefix {
		t.Fatalf("currentWANPrefix switched early: %v", wan.currentWANPrefix)
	}

	// The threshold-th (default 3) mismatching RA confirms the switch.
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	if wan.currentWANPrefix != newPrefix {
		t.Fatalf("currentWANPrefix = %v, want %v after %d mismatches", wan.currentWANPrefix, newPrefix, prefixMismatchThreshold)
	}
}

func TestTrackWANPrefixSnoopingResetsMismatchCountOnMatch(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	// A real RA of the still-current prefix in between resets the streak.
	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))

	if wan.currentWANPrefix != oldPrefix {
		t.Fatalf("currentWANPrefix = %v, want %v (mismatch streak should have been reset)", wan.currentWANPrefix, oldPrefix)
	}
}
