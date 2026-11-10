// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

// STUN protocol encoding/decoding and embedded lightweight STUN server.
// Tailscale clients send STUN binding requests containing SOFTWARE="tailnode"
// and a CRC32 FINGERPRINT attribute to discover their public reflective IP:Port.

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	attrNumSoftware      = 0x8022
	attrNumFingerprint   = 0x8028
	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
	attrXorMappedAddressAlt = 0x8020

	software       = "tailnode"
	bindingRequest = "\x00\x01"
	magicCookie    = "\x21\x12\xa4\x42"
	lenFingerprint = 8
	headerLen      = 20
)

// TxID is a STUN transaction ID.
type TxID [12]byte

func NewTxID() TxID {
	var tx TxID
	if _, err := crand.Read(tx[:]); err != nil {
		panic(err)
	}
	return tx
}

// Is reports whether b is a STUN message.
func Is(b []byte) bool {
	return len(b) >= headerLen &&
		b[0]&0b11000000 == 0 &&
		string(b[4:8]) == magicCookie
}

func fingerPrint(b []byte) uint32 { return crc32.ChecksumIEEE(b) ^ 0x5354554e }

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Request generates a STUN binding request packet.
func Request(tID TxID) []byte {
	const lenAttrSoftware = 4 + len(software)
	b := make([]byte, 0, headerLen+lenAttrSoftware+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenAttrSoftware+lenFingerprint))
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	b = appendU16(b, attrNumSoftware)
	b = appendU16(b, uint16(len(software)))
	b = append(b, software...)

	fp := fingerPrint(b)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	return b
}

var (
	ErrNotSTUN            = errors.New("response is not a STUN packet")
	ErrNotSuccessResponse = errors.New("STUN packet is not a response")
	ErrMalformedAttrs     = errors.New("STUN response has malformed attributes")
	ErrNotBindingRequest  = errors.New("STUN request not a binding request")
	ErrWrongSoftware      = errors.New("STUN request came from non-Tailscale software")
	ErrNoFingerprint      = errors.New("STUN request didn't end in fingerprint")
	ErrWrongFingerprint   = errors.New("STUN request had bogus fingerprint")
)

// ParseBindingRequest parses a STUN binding request and verifies that it
// originated from Tailscale client software.
func ParseBindingRequest(b []byte) (TxID, error) {
	if !Is(b) {
		return TxID{}, ErrNotSTUN
	}
	if string(b[:len(bindingRequest)]) != bindingRequest {
		return TxID{}, ErrNotBindingRequest
	}
	var txID TxID
	copy(txID[:], b[8:8+len(txID)])
	var softwareOK bool
	var lastAttr uint16
	var gotFP uint32
	if err := foreachAttr(b[headerLen:], func(attrType uint16, a []byte) error {
		lastAttr = attrType
		if attrType == attrNumSoftware && string(a) == software {
			softwareOK = true
		}
		if attrType == attrNumFingerprint && len(a) == 4 {
			gotFP = binary.BigEndian.Uint32(a)
		}
		return nil
	}); err != nil {
		return TxID{}, err
	}
	if !softwareOK {
		return TxID{}, ErrWrongSoftware
	}
	if lastAttr != attrNumFingerprint {
		return TxID{}, ErrNoFingerprint
	}
	wantFP := fingerPrint(b[:len(b)-lenFingerprint])
	if gotFP != wantFP {
		return TxID{}, ErrWrongFingerprint
	}
	return txID, nil
}

func foreachAttr(b []byte, fn func(attrType uint16, a []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return ErrMalformedAttrs
		}
		attrType := binary.BigEndian.Uint16(b[:2])
		attrLen := int(binary.BigEndian.Uint16(b[2:4]))
		attrLenWithPad := (attrLen + 3) &^ 3
		b = b[4:]
		if attrLenWithPad > len(b) {
			return ErrMalformedAttrs
		}
		if err := fn(attrType, b[:attrLen]); err != nil {
			return err
		}
		b = b[attrLenWithPad:]
	}
	return nil
}

// Response generates a successful STUN binding response with XOR-MAPPED-ADDRESS.
func Response(txID TxID, addrPort netip.AddrPort) []byte {
	addr := addrPort.Addr()

	var fam byte
	if addr.Is4() {
		fam = 1
	} else if addr.Is6() {
		fam = 2
	} else {
		return nil
	}
	attrsLen := 8 + addr.BitLen()/8
	b := make([]byte, 0, headerLen+attrsLen)

	b = append(b, 0x01, 0x01) // success
	b = appendU16(b, uint16(attrsLen))
	b = append(b, magicCookie...)
	b = append(b, txID[:]...)

	b = appendU16(b, attrXorMappedAddress)
	b = appendU16(b, uint16(4+addr.BitLen()/8))
	b = append(b, 0, fam)
	b = appendU16(b, addrPort.Port()^0x2112)
	ipa := addr.As16()
	for i, o := range ipa[16-addr.BitLen()/8:] {
		if i < 4 {
			b = append(b, o^magicCookie[i])
		} else {
			b = append(b, o^txID[i-len(magicCookie)])
		}
	}
	return b
}

// ParseResponse parses a STUN binding response packet and extracts the mapped address.
func ParseResponse(b []byte) (tID TxID, addr netip.AddrPort, err error) {
	if !Is(b) {
		return tID, netip.AddrPort{}, ErrNotSTUN
	}
	copy(tID[:], b[8:8+len(tID)])
	if b[0] != 0x01 || b[1] != 0x01 {
		return tID, netip.AddrPort{}, ErrNotSuccessResponse
	}
	attrsLen := int(binary.BigEndian.Uint16(b[2:4]))
	b = b[headerLen:]
	if attrsLen > len(b) {
		return tID, netip.AddrPort{}, ErrMalformedAttrs
	} else if len(b) > attrsLen {
		b = b[:attrsLen]
	}

	var fallbackAddr netip.AddrPort
	if err := foreachAttr(b, func(attrType uint16, attr []byte) error {
		switch attrType {
		case attrXorMappedAddress, attrXorMappedAddressAlt:
			ipSlice, port, err := xorMappedAddress(tID, attr)
			if err != nil {
				return err
			}
			if ip, ok := netip.AddrFromSlice(ipSlice); ok {
				addr = netip.AddrPortFrom(ip.Unmap(), port)
			}
		case attrMappedAddress:
			ipSlice, port, err := mappedAddress(attr)
			if err != nil {
				return ErrMalformedAttrs
			}
			if ip, ok := netip.AddrFromSlice(ipSlice); ok {
				fallbackAddr = netip.AddrPortFrom(ip.Unmap(), port)
			}
		}
		return nil
	}); err != nil {
		return TxID{}, netip.AddrPort{}, err
	}

	if addr.IsValid() {
		return tID, addr, nil
	}
	if fallbackAddr.IsValid() {
		return tID, fallbackAddr, nil
	}
	return tID, netip.AddrPort{}, ErrMalformedAttrs
}

func xorMappedAddress(tID TxID, b []byte) (addr []byte, port uint16, err error) {
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	xorPort := binary.BigEndian.Uint16(b[2:4])
	addrField := b[4:]
	port = xorPort ^ 0x2112

	addrLen := familyAddrLen(b[1])
	if addrLen == 0 || len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	xorAddr := addrField[:addrLen]
	addr = make([]byte, addrLen)
	for i := range xorAddr {
		if i < len(magicCookie) {
			addr[i] = xorAddr[i] ^ magicCookie[i]
		} else {
			addr[i] = xorAddr[i] ^ tID[i-len(magicCookie)]
		}
	}
	return addr, port, nil
}

func familyAddrLen(fam byte) int {
	switch fam {
	case 0x01:
		return net.IPv4len
	case 0x02:
		return net.IPv6len
	default:
		return 0
	}
}

func mappedAddress(b []byte) (addr []byte, port uint16, err error) {
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	port = uint16(b[2])<<8 | uint16(b[3])
	addrField := b[4:]
	addrLen := familyAddrLen(b[1])
	if addrLen == 0 || len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	return bytes.Clone(addrField[:addrLen]), port, nil
}

// ----------------------------------------------------------------------------
// Embedded STUN Server
// ----------------------------------------------------------------------------

type stunServer struct {
	addr      string
	pc        *net.UDPConn
	done      chan struct{}
	wg        sync.WaitGroup
	rxPackets atomic.Uint64
	txPackets atomic.Uint64
}

func newSTUNServer(addr string) (*stunServer, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN addr %q: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, fmt.Errorf("listen STUN on %v: %w", uaddr, err)
	}
	return &stunServer{
		addr: addr,
		pc:   pc,
		done: make(chan struct{}),
	}, nil
}

func (s *stunServer) start() {
	s.wg.Add(1)
	go s.serve()
	log.Printf("[STUN] server listening on %v", s.pc.LocalAddr())
}

func (s *stunServer) stop() {
	close(s.done)
	_ = s.pc.Close()
	s.wg.Wait()
	log.Printf("[STUN] server stopped (rx=%d, tx=%d)", s.rxPackets.Load(), s.txPackets.Load())
}

func (s *stunServer) Addr() string {
	if s.pc != nil {
		return s.pc.LocalAddr().String()
	}
	return s.addr
}

func (s *stunServer) serve() {
	defer s.wg.Done()
	var buf [64 << 10]byte
	for {
		n, remote, err := s.pc.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[STUN] WARN read error: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}

		pkt := buf[:n]
		if !Is(pkt) {
			continue
		}
		txID, err := ParseBindingRequest(pkt)
		if err != nil {
			continue
		}
		s.rxPackets.Add(1)

		// Unmap IPv4-mapped IPv6 address (::ffff:a.b.c.d -> a.b.c.d)
		clientAddr := netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		res := Response(txID, clientAddr)
		if len(res) == 0 {
			continue
		}

		if _, err := s.pc.WriteToUDPAddrPort(res, remote); err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("[STUN] WARN write error to %v: %v", remote, err)
			}
		} else {
			s.txPackets.Add(1)
		}
	}
}
