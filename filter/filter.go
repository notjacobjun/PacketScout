package filter

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

// BuildBpfFilter constructs the BPF filter string based on provided parameters.
func BuildBpfFilter(protocol, srcIP, dstIP, srcPort, dstPort string) string {
	var filter string
	if protocol != "" {
		filter += protocol
	}
	if srcIP != "" {
		if filter != "" {
			filter += " and "
		}
		filter += "src host " + srcIP
	}
	if dstIP != "" {
		if filter != "" {
			filter += " and "
		}
		filter += "dst host " + dstIP
	}
	if srcPort != "" {
		if filter != "" {
			filter += " and "
		}
		filter += "src port " + srcPort
	}
	if dstPort != "" {
		if filter != "" {
			filter += " and "
		}
		filter += "dst port " + dstPort
	}
	return filter
}

// SetBpfFilter applies the BPF filter to the pcap handle.
func SetBpfFilter(handle *pcap.Handle, filter string) {
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}
		fmt.Printf("BPF filter set to: %s\n", filter)
	}
}
