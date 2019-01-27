package mdns

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"

	"golang.org/x/net/ipv6"
)

var (
	multicastGroupV4 = net.IPv4(224, 0, 0, 251)
	multicastGroupV6 = net.ParseIP("ff02::fb")
	multicastAddrV4  = net.UDPAddr{IP: multicastGroupV4, Port: 5353}
	multicastAddrV6  = net.UDPAddr{IP: multicastGroupV6, Port: 5353}
)

type NoJoinMultiCastError struct{}

func (e NoJoinMultiCastError) Error() string {
	return "Could Not Join Any Multicast Group on Any Interface"
}

func joinMulticastV4() (*ipv4.PacketConn, error) {
	ifaces := GetMulticastIfaces()
	group := multicastGroupV4

	conn, err := net.ListenPacket("udp4", "224.0.0.251:5353")

	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(conn)

	var errCounter = 0
	for _, iface := range ifaces {
		if err := p.JoinGroup(&iface, &net.UDPAddr{IP: group}); err != nil {
			errCounter++
		}
	}

	if errCounter >= len(ifaces) {
		return nil, NoJoinMultiCastError{}
	}

	return p, nil
}

func joinMulticastV6() (*ipv6.PacketConn, error) {
	ifaces := GetMulticastIfaces()
	group := multicastGroupV6

	//conn, err := net.ListenPacket("udp6", "[ff02::fb]:5353")
	conn, err := net.ListenUDP("udp6", &multicastAddrV6)

	if err != nil {
		return nil, err
	}

	p := ipv6.NewPacketConn(conn)
	fmt.Println("trying to join ", len(ifaces))
	var errCounter = 0
	for _, iface := range ifaces {
		if err := p.JoinGroup(&iface, &net.UDPAddr{IP: group}); err != nil {
			errCounter++
		}
	}

	if errCounter >= len(ifaces) {
		return nil, NoJoinMultiCastError{}
	}

	return p, nil
}

func GetMulticastIfaces() []net.Interface {

	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		if ifaceIsUp(&iface) && ifaceIsMulticast(&iface) {
			ifaces = append(ifaces, iface)
		}
	}

	return ifaces
}

func ifaceIsUp(iface *net.Interface) bool {
	return (iface.Flags & net.FlagUp) > 0
}

func ifaceIsMulticast(iface *net.Interface) bool {
	return (iface.Flags & net.FlagMulticast) > 0
}
