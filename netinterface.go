package zeroconf

import (
	"net"
	"sync/atomic"
)

type NetInterface struct {
	net.Interface
	stateIPv4 NetInterfaceStateFlag
	stateIPv6 NetInterfaceStateFlag
}

type NetInterfaceScope int

const (
	NetInterfaceScopeIPv4 NetInterfaceScope = iota
	NetInterfaceScopeIPv6
)

type NetInterfaceList []*NetInterface

type NetInterfaceStateFlag uint32

const (
	NetInterfaceStateFlagMulticastJoined NetInterfaceStateFlag = 1 << iota // we have joined the multicast group on this interface
	NetInterfaceStateFlagMessageSent                                       // we have successfully sent at least one message on this interface
)

func (i *NetInterface) HasFlags(scope NetInterfaceScope, flags ...NetInterfaceStateFlag) bool {
	for _, flag := range flags {
		if !i.HasFlag(scope, flag) {
			return false
		}
	}
	return true
}

func (i *NetInterface) loadFlag(address *NetInterfaceStateFlag) NetInterfaceStateFlag {
	return NetInterfaceStateFlag(atomic.LoadUint32((*uint32)(address)))
}

func (i *NetInterface) HasFlag(scope NetInterfaceScope, flag NetInterfaceStateFlag) bool {
	if scope == NetInterfaceScopeIPv4 {
		return NetInterfaceStateFlag(i.loadFlag(&i.stateIPv4)&flag) != 0
	} else if scope == NetInterfaceScopeIPv6 {
		return NetInterfaceStateFlag(i.loadFlag(&i.stateIPv6)&flag) != 0
	}
	return false
}

func (i *NetInterface) SetFlag(scope NetInterfaceScope, flag NetInterfaceStateFlag) {
	if scope == NetInterfaceScopeIPv4 {
		i.setFlag(&i.stateIPv4, flag)
	} else if scope == NetInterfaceScopeIPv6 {
		i.setFlag(&i.stateIPv6, flag)
	}
}

func (i *NetInterface) setFlag(address *NetInterfaceStateFlag, flag NetInterfaceStateFlag) {
	// If atomic value != previously loaded value, then repeat the operation
	// If they are equal, then we can safely set the new value
	// This is the way to ensure atomicity of the operation
	for {
		loadedValue := uint32(i.loadFlag(address))
		if atomic.CompareAndSwapUint32((*uint32)(address), loadedValue, loadedValue|uint32(flag)) {
			break
		}
	}
}

func (list NetInterfaceList) GetByIndex(index int) *NetInterface {
	for _, iface := range list {
		if iface.Index == index {
			return iface
		}
	}
	return nil
}

func NewInterfaceList(ifaces []net.Interface) (list NetInterfaceList) {
	for i := range ifaces {
		list = append(list, &NetInterface{Interface: ifaces[i]})
	}
	return
}
