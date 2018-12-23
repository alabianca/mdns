package mdns

import "net"

//New returns a configured mdns server
//listening @ 224.0.0.251:5353
func New() (*Server, error) {
	serv := Server{
		address: "224.0.0.251:5353",
	}
	addr, addrErr := net.ResolveUDPAddr("udp", serv.address)

	me, notFound := getMyIpv4Addr()

	if notFound != nil {
		return nil, notFound
	}

	if addrErr != nil {
		return nil, addrErr
	}

	pc, err := net.ListenMulticastUDP("udp4", nil, addr)

	if err != nil {
		return nil, err
	}

	conn, connErr := net.DialUDP("udp4", nil, addr)

	if connErr != nil {
		return nil, connErr
	}

	serv.conn = conn
	serv.multicastConn = pc
	serv.me = me
	serv.entries = make(map[string]serviceEntry)

	return &serv, nil
}
