package mdns

import (
	"fmt"

	"github.com/alabianca/dnsPacket"
	"golang.org/x/net/ipv6"
)

func RegisterService(serviceName string) error {
	return fmt.Errorf("Error")
}

func announce(serviceName string, conn *ipv6.PacketConn) {
	packet := dnsPacket.DNSPacket{
		Type:    "response",
		ID:      1,
		Qdcount: 0,
		Ancount: 1,
		Nscount: 0,
		Arcount: 0,
	}

	record := dnsPacket.RecordTypeSRV{
		Port:     4000,
		Priority: 0,
		Weight:   0,
		Target:   "alexander.local",
	}

	encoded := record.Encode()

	packet.AddAnswer(serviceName, 1, 33, 0, len(encoded), encoded)

	msg := dnsPacket.Encode(&packet)
	fmt.Println(msg)

	ifaces := GetMulticastIfaces()

	for _, i := range ifaces {
		control := ipv6.ControlMessage{IfIndex: i.Index}
		conn.WriteTo(msg, &control, &multicastAddrV6)
	}

}
