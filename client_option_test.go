package zeroconf

import "testing"

func TestUnannouncementsOption(t *testing.T) {
	if !applyOpts(Unannouncements()).unannouncements {
		t.Fatal("Unannouncements did not enable removal events")
	}
}
