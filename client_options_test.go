package zeroconf

import (
	"testing"
	"time"
)

func TestRefreshCachedEntryExtendsExpiry(t *testing.T) {
	originalExpiry := time.Now().Add(time.Second)
	refreshedExpiry := originalExpiry.Add(10 * time.Second)
	cached := &ServiceEntry{Expiry: originalExpiry}
	sent := map[string]*ServiceEntry{"service": cached}

	if !refreshCachedEntry(sent, "service", &ServiceEntry{Expiry: refreshedExpiry}) {
		t.Fatal("cached entry was not recognized")
	}
	if !cached.Expiry.Equal(refreshedExpiry) {
		t.Fatalf("cached expiry = %s, want %s", cached.Expiry, refreshedExpiry)
	}
	if refreshCachedEntry(sent, "other", &ServiceEntry{Expiry: refreshedExpiry}) {
		t.Fatal("unknown entry was reported as cached")
	}
}
