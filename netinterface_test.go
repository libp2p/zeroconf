package zeroconf

import (
	"sync"
	"testing"
	"time"
)

func TestSetFlagSimple(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		iface := &NetInterface{}
		iface.SetFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined)
		if !iface.HasFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined) {
			t.Error("expect true")
		}
		if iface.HasFlags(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined, NetInterfaceStateFlagMessageSent) {
			t.Error("expect false")
		}

		iface.SetFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMessageSent)
		if !iface.HasFlags(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined, NetInterfaceStateFlagMessageSent) {
			t.Error("expect true")
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		iface := &NetInterface{}
		iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMessageSent)
		if !iface.HasFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMessageSent) {
			t.Error("expect true")
		}
		if iface.HasFlags(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined, NetInterfaceStateFlagMessageSent) {
			t.Error("expect false")
		}

		iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined)
		if !iface.HasFlags(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined, NetInterfaceStateFlagMessageSent) {
			t.Error("expect true")
		}
	})
}

func TestSetFlagConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		iface := &NetInterface{}
		wg.Add(2)
		go func() {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				if j%2 == 0 {
					iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined)
				} else {
					iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMessageSent)
				}
			}
		}()
		go func() {
			defer wg.Done()

			var eventuallyOk bool
			for j := 0; j < 10; j++ {
				eventuallyOk = iface.HasFlags(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined, NetInterfaceStateFlagMessageSent)
				time.Sleep(time.Millisecond)
			}
			if !eventuallyOk {
				t.Error("expect true")
			}
		}()
	}
	wg.Wait()
}
