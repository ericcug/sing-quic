package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// UDPAssociationMarker is the bounded Open payload used to distinguish a
// SOCKS UDP-associate session from a TCP destination. It is intentionally not
// a valid host:port string, so a future TCP destination cannot collide with
// the UDP control plane.
var UDPAssociationMarker = []byte{'W', 'O', 'U', 'D', 1}

const (
	packetDestinationLength = 2
	packetHeaderLength      = packetDestinationLength
	maxUDPPayload           = 65507
)

// These numbers together fix the largest frame protocol 1 can require a
// receiver to accept, which is why protocol.MaxPayload is the size it is. They
// are exported so the conformance vectors can state that relationship rather
// than leave it a coincidence between two packages.
const (
	// MaxDestinationLength bounds the canonical host:port a frame may name.
	MaxDestinationLength = maxDestinationLength
	// MaxUDPDatagram is the largest datagram a PACKET frame may carry: 65535
	// less the 20-byte IP and 8-byte UDP headers.
	MaxUDPDatagram = maxUDPPayload
	// PacketDestinationPrefix is the width of a PACKET payload's leading
	// destination-length field.
	PacketDestinationPrefix = packetDestinationLength
	// MaxPacketPayload is the largest legal PACKET payload, and therefore the
	// floor under any receiver's frame payload limit.
	MaxPacketPayload = PacketDestinationPrefix + MaxDestinationLength + MaxUDPDatagram
)

func IsUDPAssociation(payload []byte) bool {
	return string(payload) == string(UDPAssociationMarker)
}

// EncodeUDPPacket stores one canonical target and one UDP payload. The
// destination length is explicit and bounded so malformed packets can be
// rejected before a resolver or socket operation is attempted.
func EncodeUDPPacket(destination string, payload []byte) ([]byte, error) {
	destinationBytes, err := EncodeDestination(destination)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxUDPPayload {
		return nil, fmt.Errorf("UDP payload exceeds %d bytes", maxUDPPayload)
	}
	if len(destinationBytes) > 65535 || len(destinationBytes)+packetHeaderLength+len(payload) > maxUDPPayload+maxDestinationLength+packetHeaderLength {
		return nil, errors.New("UDP packet exceeds bounded payload")
	}
	out := make([]byte, packetHeaderLength+len(destinationBytes)+len(payload))
	binary.BigEndian.PutUint16(out[:packetDestinationLength], uint16(len(destinationBytes)))
	copy(out[packetHeaderLength:], destinationBytes)
	copy(out[packetHeaderLength+len(destinationBytes):], payload)
	return out, nil
}

func DecodeUDPPacket(payload []byte) (destination string, packet []byte, err error) {
	if len(payload) < packetHeaderLength+1 {
		return "", nil, errors.New("UDP packet is truncated")
	}
	destinationLength := int(binary.BigEndian.Uint16(payload[:packetDestinationLength]))
	if destinationLength == 0 || destinationLength > maxDestinationLength || packetHeaderLength+destinationLength > len(payload) {
		return "", nil, errors.New("invalid UDP destination length")
	}
	destinationBytes := payload[packetHeaderLength : packetHeaderLength+destinationLength]
	destination, err = DecodeDestination(destinationBytes)
	if err != nil {
		return "", nil, fmt.Errorf("invalid UDP destination: %w", err)
	}
	packet = payload[packetHeaderLength+destinationLength:]
	if len(packet) > maxUDPPayload {
		return "", nil, errors.New("invalid UDP payload length")
	}
	return destination, append([]byte(nil), packet...), nil
}

// DestinationFromUDPAddr canonicalizes an address received from a remote
// datagram socket. UDP replies always use numeric addresses, avoiding a DNS
// lookup on the client side and preventing a response from being redirected
// by later DNS changes.
func DestinationFromUDPAddr(addr *net.UDPAddr) (string, error) {
	if addr == nil || addr.Port < 1 || addr.Port > 65535 || addr.IP == nil {
		return "", errors.New("invalid UDP source address")
	}
	return net.JoinHostPort(addr.IP.String(), fmt.Sprintf("%d", addr.Port)), nil
}
