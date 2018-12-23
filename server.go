package mdns

import (
	"net"
	"time"

	"github.com/alabianca/dnsPacket"
)

type serviceEntry struct {
	IP       string
	Port     uint16
	Host     string
	Weight   uint16
	TTL      uint32
	Priority uint16
	Name     string
}

//Server is a mdns server
type Server struct {
	address       string
	multicastConn *net.UDPConn
	conn          *net.UDPConn
	entries       map[string]serviceEntry
	me            net.IP
}

func (s *Server) LookupSRV(name string) dnsPacket.RecordTypeSRV {
	result := make(chan dnsPacket.RecordTypeSRV)

	go func(found chan dnsPacket.RecordTypeSRV) {
		buffer := make([]byte, 1024)

		for {
			_, sender, _ := s.multicastConn.ReadFromUDP(buffer)

			decoded := dnsPacket.Decode(buffer)

			if decoded.Type == "response" && decoded.Ancount >= 0 {
				answer := decoded.Answers[0]

				//is an srv record and the sender is not myself and the answer name is actually what we are looking for
				if answer.Type == 33 && !sender.IP.Equal(s.me) && answer.Name == name {
					record := answer.Process()

					found <- *record.(*dnsPacket.RecordTypeSRV)
				}
			}
		}
	}(result)

	//Query every 500 milliseconds until we found a match ...
	for {
		select {
		case record := <-result:
			return record
		default:
			s.Query(name, "IN", "SRV")
			time.Sleep(time.Millisecond * 500)
		}
	}
}

func (s *Server) LookupA(name string) dnsPacket.RecordTypeA {
	result := make(chan dnsPacket.RecordTypeA)

	go func(found chan dnsPacket.RecordTypeA) {
		buffer := make([]byte, 1024)

		for {
			_, sender, _ := s.multicastConn.ReadFromUDP(buffer)

			decoded := dnsPacket.Decode(buffer)

			if decoded.Type == "response" && decoded.Ancount >= 0 {
				answer := decoded.Answers[0]

				//is an srv record and the sender is not myself and the answer name is actually what we are looking for
				if answer.Type == 1 && !sender.IP.Equal(s.me) && answer.Name == name {
					record := answer.Process()

					found <- *record.(*dnsPacket.RecordTypeA)
				}
			}
		}
	}(result)

	//Query every 500 milliseconds until we found a match ...
	for {
		select {
		case record := <-result:
			return record
		default:
			s.Query(name, "IN", "A")
			time.Sleep(time.Millisecond * 500)
		}
	}
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

func (s *Server) Respond(name string, anType int, queryPacket dnsPacket.DNSPacket, responseData []byte) {

	queryPacket.AddAnswer(name, 1, anType, 500, len(responseData), responseData)

	queryPacket.Type = "response"
	queryPacket.Ancount = queryPacket.Ancount + 1

	s.conn.Write(dnsPacket.Encode(&queryPacket))
}

func (s *Server) Advertise() chan dnsPacket.DNSPacket {
	responseChannel := make(chan dnsPacket.DNSPacket)

	go func(onResponse chan dnsPacket.DNSPacket) {
		buffer := make([]byte, 1024)
		for {
			s.multicastConn.ReadFromUDP(buffer)

			decoded := dnsPacket.Decode(buffer)

			//1. is packet a dns query?
			if decoded.Type == "query" && decoded.Qdcount > 0 {
				handleQuery(s, *decoded)
			}

			if decoded.Type == "response" {
				onResponse <- *decoded
			}
		}

	}(responseChannel)

	return responseChannel
}

func (s *Server) RegisterService(name string, host string, ip string, port uint16, ttl uint32, priority uint16, weight uint16) {

	service := serviceEntry{
		Name:     name,
		Host:     host,
		IP:       ip,
		Port:     port,
		TTL:      ttl,
		Priority: priority,
		Weight:   weight,
	}

	s.entries[name] = service
	s.entries[host] = service
}

func handleQuery(s *Server, packet dnsPacket.DNSPacket) bool {
	//look at the first question only
	question := packet.Questions[0]

	service, ok := s.entries[question.Qname]

	//we don't have the service registered. just return...
	if !ok {
		return false
	}

	var record dnsPacket.PacketProcessor
	switch question.Qtype {
	case 1:
		record = &dnsPacket.RecordTypeA{
			IPv4: service.IP,
		}

	case 33:
		record = &dnsPacket.RecordTypeSRV{
			Target:   service.Host,
			Weight:   service.Weight,
			Port:     service.Port,
			Priority: service.Priority,
		}
	}

	s.Respond(question.Qname, question.Qtype, packet, record.Encode())

	return true

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
