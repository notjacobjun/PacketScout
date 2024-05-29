package filter

import (
	"fmt"
	"net"

	"network_packet_sniffer/parse"
)

type PacketFilter struct {
	Protocols        []uint8
	SourceIPs        []net.IP
	DestinationIPs   []net.IP
	SourcePorts      []uint16
	DestinationPorts []uint16
}

func (filter *PacketFilter) Match(packet []byte) bool {
	// ethHeader := parse.ParseEthernetHeader(packet[:14])
	// if ethHeader.EtherType != 0x0800 { // Only process IPv4 packets
	// 	fmt.Println("False because not IPv4")
	// 	return false

	ipv4Header := parse.ParseIPv4Header(packet[14:34])
	if len(filter.Protocols) > 0 && !containsProtocol(filter.Protocols, ipv4Header.Protocol) {
		fmt.Println("False because of incorrect protocol filter")
		return false
	}

	if len(filter.SourceIPs) > 0 && !containsIP(filter.SourceIPs, ipv4Header.SrcIP) {
		fmt.Println("False because of incorrect source IP")
		return false
	}

	if len(filter.DestinationIPs) > 0 && !containsIP(filter.DestinationIPs, ipv4Header.DestIP) {
		fmt.Println("False because incorrect destination IP")
		return false
	}

	// check ports based on TCP and UDP protocols because they are in different bits based on the protocols
	if ipv4Header.Protocol == 6 { // TCP
		tcpHeader := parse.ParseTCPHeader(packet[34:54])
		if len(filter.SourcePorts) > 0 && !containsPort(filter.SourcePorts, tcpHeader.SrcPort) {
			fmt.Println("False because incorrect source port for TCP")
			return false
		}
		if len(filter.DestinationPorts) > 0 && !containsPort(filter.DestinationPorts, tcpHeader.DestPort) {
			fmt.Println("False because incorrect destination port for TCP")
			return false
		}
	} else if ipv4Header.Protocol == 17 { // UDP
		udpHeader := parse.ParseUDPHeader(packet[34:42])
		if len(filter.SourcePorts) > 0 && !containsPort(filter.SourcePorts, udpHeader.SrcPort) {
			fmt.Println("False because incorrect source port for UDP")
			return false
		}
		if len(filter.DestinationPorts) > 0 && !containsPort(filter.DestinationPorts, udpHeader.DestPort) {
			fmt.Println("False because incorrect destination port for UDP")
			return false
		}
	}
	return true
}

func containsProtocol(protocols []uint8, protocol uint8) bool {
	for _, p := range protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

func containsIP(ips []net.IP, ip net.IP) bool {
	for _, i := range ips {
		if i.Equal(ip) {
			return true
		}
	}
	return false
}

func containsPort(ports []uint16, port uint16) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
