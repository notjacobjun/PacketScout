package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"network_packet_sniffer/filter"
	"network_packet_sniffer/parse"
)

func main() {
	// TODO change this to be a command line argument
	iface := "en0"

	fd, err := openBPF()
	if err != nil {
		log.Fatalf("Failed to open BPF: %v", err)
	}
	defer syscall.Close(fd)

	if err := bindToInterface(fd, iface); err != nil {
		log.Fatalf("Failed to bind to interface %s: %v", iface, err)
	}

	// Set up signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\nReceived interrupt, shutting down...")
		os.Exit(0)
	}()

	bufSize := 4096
	buf := make([]byte, bufSize)

	filter := filter.PacketFilter{
		// Protocols:      []uint8{6, 17}, // TCP and UDP
		Protocols:      []uint8{}, // TCP and UDP
		SourceIPs:      []net.IP{},
		DestinationIPs: []net.IP{},
		// SourceIPs:        []net.IP{net.ParseIP(os.Getenv("SRC_IP"))},
		// DestinationIPs:   []net.IP{net.ParseIP("DEST_IP")},
		SourcePorts:      []uint16{},
		DestinationPorts: []uint16{},
	}

	for {
		// NOTE that n is the number of bytes successfully read
		n, err := readWithRetry(fd, buf)
		fmt.Printf("Read %d bytes from the package\n", n)
		if err != nil {
			log.Fatalf("Failed to read from BPF: %v", err)
		}
		if n > 0 && filter.Match(buf[:n]) { // there is some network package of interest
			fmt.Printf("Captured packet: %x\n", buf[:n])
			ethernetHeader := parse.ParseEthernetHeader(buf[:14])
			fmt.Printf("Ethernet Header: %+v\n", ethernetHeader)

			if ethernetHeader.EtherType == 0x0800 { // IPv4
				ipv4Header := parse.ParseIPv4Header(buf[14:])
				fmt.Printf("IPv4 Header: %+v\n", ipv4Header)
				ipHeaderLength := int(ipv4Header.VersionIHL & 0x0F * 4)
				payloadOffset := 14 + ipHeaderLength

				if ipv4Header.Protocol == 6 { // TCP
					tcpHeader := parse.ParseTCPHeader(buf[payloadOffset:])
					fmt.Printf("TCP Header: %+v\n", tcpHeader)
				} else if ipv4Header.Protocol == 17 { // UDP
					udpHeader := parse.ParseUDPHeader(buf[payloadOffset:])
					fmt.Printf("UDP Header: %+v\n", udpHeader)
				}
			}
		} else {
			// No data read, add a small delay before retrying
			fmt.Printf("Retrying the read and parse logic. Failed with err: %v and match res: %v\n", err, filter.Match(buf[:n]))
			time.Sleep(1000 * time.Millisecond)
		}
	}
}

func readWithRetry(fd int, buf []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				// Interrupted system call, retry reading
				continue
			} else if err == syscall.EAGAIN {
				// No data available, return 0 bytes read
				return 0, nil
			}
			return n, err
		}
		return n, nil
	}
}

func openBPF() (int, error) {
	for i := 0; i < 255; i++ {
		device := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(device, syscall.O_RDWR, 0)
		if err == nil {
			// Set non-blocking mode
			if err := syscall.SetNonblock(fd, true); err != nil {
				syscall.Close(fd)
				return -1, fmt.Errorf("failed to set non-blocking mode: %v", err)
			}
			log.Printf("Opened BPF device: %s", device)
			return fd, nil
		}
		if err != syscall.EBUSY {
			log.Printf("Failed to open BPF device %s: %v", device, err)
		}
	}
	return -1, fmt.Errorf("no BPF devices available")
}

func bindToInterface(fd int, iface string) error {
	ifr := struct {
		Name [syscall.IFNAMSIZ]byte
	}{}

	// copy the iface into it
	copy(ifr.Name[:], iface)

	// bind the BPF device to the network interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCSETIF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("ioctl BIOCSETIF failed (failed to set the network interface for the BPF device): %v", errno)
	}

	// set immediate mode for the network interface (sending the packets to the BPF device as soon as we get it)
	var enable int = 1
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.BIOCIMMEDIATE, uintptr(unsafe.Pointer(&enable)))
	if errno != 0 {
		return fmt.Errorf("ioctl BIOCIMMEDIATE failed: %v", errno)
	}
	return nil
}
