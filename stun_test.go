// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSTUNServer(t *testing.T) {
	server, err := newSTUNServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start stun server: %v", err)
	}
	server.start()
	defer server.stop()

	serverUDPAddr := server.pc.LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp", nil, serverUDPAddr)
	if err != nil {
		t.Fatalf("failed to dial stun server: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	txID := NewTxID()
	req := Request(txID)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("failed to send STUN request: %v", err)
	}

	var buf [1024]byte
	n, err := client.Read(buf[:])
	if err != nil {
		t.Fatalf("failed to read STUN response: %v", err)
	}

	respTxID, addrPort, err := ParseResponse(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse STUN response: %v", err)
	}

	if respTxID != txID {
		t.Fatalf("txID mismatch: got %v, want %v", respTxID, txID)
	}

	clientLocalAddrPort := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if addrPort != clientLocalAddrPort {
		t.Fatalf("reported address mismatch: got %v, want %v", addrPort, clientLocalAddrPort)
	}
}

func TestSTUNWrongSoftwareRejected(t *testing.T) {
	// A generic STUN packet with bogus software or no software should be rejected
	txID := NewTxID()
	// Raw minimal binding request without SOFTWARE attribute
	b := []byte{
		0x00, 0x01, 0x00, 0x00, // Binding Request, length 0
		0x21, 0x12, 0xa4, 0x42, // Magic Cookie
	}
	b = append(b, txID[:]...)

	_, err := ParseBindingRequest(b)
	if err == nil {
		t.Fatalf("expected error for request missing tailnode software attribute, got nil")
	}
}

func TestSTUNRoundtripDualStack(t *testing.T) {
	txID := NewTxID()
	ipv4 := netip.MustParseAddrPort("1.2.3.4:5678")
	resp4 := Response(txID, ipv4)
	parsedTxID4, parsedAddr4, err := ParseResponse(resp4)
	if err != nil {
		t.Fatalf("failed to parse IPv4 response: %v", err)
	}
	if parsedTxID4 != txID || parsedAddr4 != ipv4 {
		t.Fatalf("IPv4 mismatch: got (%v, %v), want (%v, %v)", parsedTxID4, parsedAddr4, txID, ipv4)
	}

	ipv6 := netip.MustParseAddrPort("[2403:18c0::1]:9999")
	resp6 := Response(txID, ipv6)
	parsedTxID6, parsedAddr6, err := ParseResponse(resp6)
	if err != nil {
		t.Fatalf("failed to parse IPv6 response: %v", err)
	}
	if parsedTxID6 != txID || parsedAddr6 != ipv6 {
		t.Fatalf("IPv6 mismatch: got (%v, %v), want (%v, %v)", parsedTxID6, parsedAddr6, txID, ipv6)
	}
}
