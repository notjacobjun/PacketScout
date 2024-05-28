package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"network_packet_sniffer/parse"
	"unsafe"
)

func main() {
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

	for {
		n, err := readWithRetry(fd, buf)
		ethernetHeader := parse.EthernetHeader{}
		if err != nil {
			log.Fatalf("Failed to read from BPF: %v", err)
		} else if len(buf[:n]) != 0 { // there is some network package of interest
			fmt.Printf("Captured packet: %x\n", buf[:n])
			ethernetHeader = parse.ParseEthernetHeader(buf[:14])
			fmt.Printf("Ethernet Header: %+v\n", ethernetHeader)
		}

		if ethernetHeader.EtherType == 0x0800 { // IPv4
			ipv4Header := parse.ParseIPv4Header(buf[14:34])
			fmt.Printf("IPv4 Header: %+v\n", ipv4Header)

			if ipv4Header.Protocol == 6 { // TCP
				tcpHeader := parse.ParseTCPHeader(buf[34:54])
				fmt.Printf("TCP Header: %+v\n", tcpHeader)
			} else if ipv4Header.Protocol == 17 { // UDP
				udpHeader := parse.ParseUDPHeader(buf[34:42])
				fmt.Printf("UDP Header: %+v\n", udpHeader)
			}
		}
	}
}

func readWithRetry(fd int, buf []byte) (int, error) {
	for {
		// fmt.Printf("Trying to open file descriptor %d\n", fd)
		n, err := syscall.Read(fd, buf)
		// fmt.Printf("Error: %v\n", err)
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
