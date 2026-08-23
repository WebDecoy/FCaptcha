package main

import "testing"

func TestNetworkIdentityUsesIPv4Slash24AndIPv6Slash56(t *testing.T) {
	if NetworkIdentity("192.0.2.1") != NetworkIdentity("192.0.2.254") {
		t.Fatal("addresses in one IPv4 /24 should share an identity")
	}
	if NetworkIdentity("192.0.2.1") == NetworkIdentity("192.0.3.1") {
		t.Fatal("addresses in different IPv4 /24s should differ")
	}
	if NetworkIdentity("2001:db8:abcd:1200::1") != NetworkIdentity("2001:db8:abcd:12ff::2") {
		t.Fatal("addresses in one IPv6 /56 should share an identity")
	}
	if NetworkIdentity("2001:db8:abcd:1200::1") == NetworkIdentity("2001:db8:abcd:1300::1") {
		t.Fatal("addresses in different IPv6 /56s should differ")
	}
}
