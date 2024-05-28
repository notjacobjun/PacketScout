package parse

import (
	"encoding/binary"
	"net"
)

type EthernetHeader struct {
	DestMAC   net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
}

type IPv4Header struct {
	VersionIHL     uint8
	DSCP           uint8
	TotalLength    uint16
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP, DestIP  net.IP
}

type TCPHeader struct {
	SrcPort       uint16
	DestPort      uint16
	SeqNum        uint32
	AckNum        uint32
	DataOffsetRes uint8
	Flags         uint8
	Window        uint16
	Checksum      uint16
	UrgentPointer uint16
}

type UDPHeader struct {
	SrcPort  uint16
	DestPort uint16
	Length   uint16
	Checksum uint16
}

func ParseEthernetHeader(data []byte) EthernetHeader {
	return EthernetHeader{
		DestMAC:   net.HardwareAddr(data[0:6]),
		SrcMAC:    net.HardwareAddr(data[6:12]),
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}
}

func ParseIPv4Header(data []byte) IPv4Header {
	return IPv4Header{
		VersionIHL:     data[0],
		DSCP:           data[1],
		TotalLength:    binary.BigEndian.Uint16(data[2:4]),
		Identification: binary.BigEndian.Uint16(data[4:6]),
		FlagsFragment:  binary.BigEndian.Uint16(data[6:8]),
		TTL:            data[8],
		Protocol:       data[9],
		HeaderChecksum: binary.BigEndian.Uint16(data[10:12]),
		SrcIP:          net.IP(data[12:16]),
		DestIP:         net.IP(data[16:20]),
	}
}

func ParseTCPHeader(data []byte) TCPHeader {
	return TCPHeader{
		SrcPort:       binary.BigEndian.Uint16(data[0:2]),
		DestPort:      binary.BigEndian.Uint16(data[2:4]),
		SeqNum:        binary.BigEndian.Uint32(data[4:8]),
		AckNum:        binary.BigEndian.Uint32(data[8:12]),
		DataOffsetRes: data[12],
		Flags:         data[13],
		Window:        binary.BigEndian.Uint16(data[14:16]),
		Checksum:      binary.BigEndian.Uint16(data[16:18]),
		UrgentPointer: binary.BigEndian.Uint16(data[18:20]),
	}
}

func ParseUDPHeader(data []byte) UDPHeader {
	return UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DestPort: binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}
}
