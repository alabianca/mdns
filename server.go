package mdns

import (
	"net"

	"github.com/alabianca/dnsPacket"
)

//Server is a mdns server
type Server struct {
	address       string
	multicastConn *net.UDPConn
	conn          *net.UDPConn
	me            net.IP
	ResponseChan  chan dnsPacket.DNSPacket
	QueryChan     chan dnsPacket.DNSPacket
}

//Browse for other devices in the local network
func (s *Server) Browse() {
	go func() {
		buffer := make([]byte, 1024)

		for {
			_, sender, _ := s.multicastConn.ReadFromUDP(buffer)
			if sender.IP.Equal(s.me) {
				continue
			}

			decoded := dnsPacket.Decode(buffer)
			switch decoded.Type {
			case "response":
				s.ResponseChan <- *decoded
			case "query":
				s.QueryChan <- *decoded
			}
		}
	}()
}

//Query queries for a record on the local network
func (s *Server) Query(name string, class string, qType string) {
	queryType := mapType(qType)
	queryClass := mapClass(class)

	packet := dnsPacket.DNSPacket{
		Type:    "query",
		ID:      1,
		Opcode:  0,
		Flags:   0,
		Qdcount: 1,
	}

	packet.AddQuestion(name, queryClass, queryType)

	s.conn.Write(dnsPacket.Encode(&packet))

}

//Respond to a Query
func (s *Server) Respond(name string, anType int, queryPacket dnsPacket.DNSPacket, responseData []byte) {

	queryPacket.AddAnswer(name, 1, anType, 500, len(responseData), responseData)

	queryPacket.Type = "response"
	queryPacket.Ancount = queryPacket.Ancount + 1

	s.conn.Write(dnsPacket.Encode(&queryPacket))

	//fmt.Println("Just responded to ", anType)
}

//todo: map other classes
func mapClass(class string) int {
	var result int

	switch class {
	case "IN":
		result = 1
	default:
		result = 1
	}

	return result
}

func mapType(qType string) int {
	var result int

	switch qType {
	case "A":
		result = 1
	case "AAAA":
		result = 28
	case "AFSDB":
		result = 18
	case "APL":
		result = 42
	case "CAA":
		result = 257
	case "CDNSKEY":
		result = 60
	case "CDS":
		result = 59
	case "CERT":
		result = 37
	case "CNAME":
		result = 5
	case "DHCID":
		result = 49
	case "DLV":
		result = 32769
	case "DNAME":
		result = 39
	case "DNSKEY":
		result = 48
	case "DS":
		result = 43
	case "HIP":
		result = 55
	case "IPSECKEY":
		result = 45
	case "KEY":
		result = 25
	case "KX":
		result = 36
	case "LOC":
		result = 29
	case "MX":
		result = 15
	case "NAPTR":
		result = 35
	case "NS":
		result = 2
	case "NSEC":
		result = 47
	case "NSEC3":
		result = 50
	case "NSEC3PARAM":
		result = 51
	case "OPENPGPKEY":
		result = 61
	case "PTR":
		result = 12
	case "RRSIG":
		result = 46
	case "RP":
		result = 17
	case "SIG":
		result = 24
	case "SMIMEA":
		result = 53
	case "SOA":
		result = 6
	case "SRV":
		result = 33
	case "SSHFP":
		result = 44
	case "TA":
		result = 32768
	case "TKEY":
		result = 249
	case "TLSA":
		result = 52
	case "TSIG":
		result = 250
	case "TXT":
		result = 16
	case "URI":
		result = 256
	default:
		result = 1
	}

	return result
}
