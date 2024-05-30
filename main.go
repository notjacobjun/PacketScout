package main

import (
	"flag"
	"fmt"
	"log"
	"network_packet_sniffer/filter"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const IS_CAPTURING_EXTERNAL_PACKETS = false

func main() {
	var (
		device   string
		protocol string
		srcIP    string
		dstIP    string
		srcPort  string
		dstPort  string
	)
	flag.StringVar(&device, "i", "", "Network interface to capture from")
	flag.StringVar(&protocol, "p", "", "Protocol (tcp, udp, icmp, etc.)")
	flag.StringVar(&srcIP, "src-ip", "", "Source IP address")
	flag.StringVar(&dstIP, "dst-ip", "", "Destination IP address")
	flag.StringVar(&srcPort, "src-port", "", "Source port")
	flag.StringVar(&dstPort, "dst-port", "", "Destination port")

	flag.Parse()

	// Ensure the network interface is provided
	if device == "" {
		fmt.Printf("Usage: %s -i <network interface> [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Open the device for capturing
	handle, err := pcap.OpenLive(device, 1600, IS_CAPTURING_EXTERNAL_PACKETS, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	// Build and set the BPF filter
	filterStr := filter.BuildBpfFilter(protocol, srcIP, dstIP, srcPort, dstPort)
	filter.SetBpfFilter(handle, filterStr)

	fmt.Printf("Capturing on device %s\n", device)

	// Use the packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process the packet here
		fmt.Println(packet)
	}
}
