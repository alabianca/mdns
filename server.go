package mdns

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Server struct {
	ipv4                net.IP
	ipv6                net.IP
	ipv4MulticastGroup  net.UDPAddr
	ipv6MulticastGroup  net.UDPAddr
	ipv4Conn            *ipv4.PacketConn
	ipv6Conn            *ipv6.PacketConn
	connectedInterfaces []net.Interface
}

func NewMdnsServer() (*Server, error) {
	allInterfaces := GetMulticastIfaces()
	c6, e6 := joinMulticastV6()
	c4, e4 := joinMulticastV4()

	if c4 == nil && c6 == nil {
		return nil, fmt.Errorf("Could Not Join any multicast interfaces. No Connection available")
	}

	server := &Server{
		ipv4:                multicastGroupV4,
		ipv6:                multicastGroupV6,
		ipv4MulticastGroup:  multicastAddrV4,
		ipv6MulticastGroup:  multicastAddrV6,
		ipv4Conn:            c4,
		ipv6Conn:            c6,
		connectedInterfaces: allInterfaces,
	}

	return server, nil
}

func (s *Server) RegisterService() {}
