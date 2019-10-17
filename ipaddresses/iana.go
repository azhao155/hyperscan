package ipaddresses

// IANA data source: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
var ianaSpecialPurposeAddresses = [...]string{
	"0.0.0.0/8",          // This host on this network
	"10.0.0.0/8",         // Private-Use
	"100.64.0.0/10",      // Shared Address Space
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link Local
	"172.16.0.0/12",      // Private-Use
	"192.0.0.0/24",       // IETF Protocol Assignments
	"192.0.0.0/29",       // IPv4 Service Continuity Prefix
	"192.0.0.8/32",       // IPv4 dummy address
	"192.0.0.9/32",       // Port Control Protocol Anycast
	"192.0.0.10/32",      // Traversal Using Relays around NAT Anycast
	"192.0.0.170/32",     // NAT64/DNS64 Discovery
	"192.0.0.171/32",     // NAT64/DNS64 Discovery
	"192.0.2.0/24",       // Documentation (TEST-NET-1)
	"192.31.196.0/24",    // AS112-v4
	"192.52.193.0/24",    // AMT
	"192.88.99.0/24",     // Deprecated (6to4 Relay Anycast)
	"192.168.0.0/16",     // Private-Use
	"192.175.48.0/24",    // Direct Delegation AS112 Service
	"198.18.0.0/15",      // Benchmarking
	"198.51.100.0/24",    // Documentation (TEST-NET-2)
	"203.0.113.0/24",     // Documentation (TEST-NET-3)
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Limited Broadcast
}

// IsSpecialPurposeAddress checks if an IP address is an IANA special purpose address
func IsSpecialPurposeAddress(ipAddr string) (special bool, err error) {
	for _, reservedSpace := range ianaSpecialPurposeAddresses {
		special, err = InAddressSpace(ipAddr, reservedSpace)

		if special || err != nil {
			return
		}
	}
	return
}
