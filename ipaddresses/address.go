package ipaddresses

import (
	"fmt"
	"strconv"
	"strings"
)

const errInvalidIPAddrFmt = "invalid IP address: %s"
const errInvalidCIDRFmt = "invalid CIDR Notation: %s"

// ParseIPAddress is a utility function that converts IP address
// from octet notation (*.*.*.*) to its 32-bit unsigned integer value.
func ParseIPAddress(ipAddr string) (ip uint32, err error) {
	octets := strings.Split(ipAddr, ".")
	if len(octets) != 4 {
		err = fmt.Errorf(errInvalidIPAddrFmt, ipAddr)
		return
	}

	for _, octet := range octets {
		var b int

		b, err = strconv.Atoi(octet)
		if err != nil || b < 0 || b > 255 {
			err = fmt.Errorf(errInvalidIPAddrFmt, ipAddr)
			return
		}

		ip <<= 8
		ip |= uint32(b)
	}

	return ip, nil
}

// ParseCIDR converts a CIDR notation into a 32-bit unsigned integer
// prefix of an IP address space and its corresponding mask.
func ParseCIDR(cidr string) (prefix uint32, mask uint32, err error) {
	splitted := strings.Split(cidr, "/")
	if len(splitted) != 2 {
		err = fmt.Errorf(errInvalidCIDRFmt, cidr)
		return
	}

	ipAddr, suffix := splitted[0], splitted[1]
	ip, err := ParseIPAddress(ipAddr)
	if err != nil {
		err = fmt.Errorf(errInvalidCIDRFmt, cidr)
		return
	}

	bits, err := strconv.Atoi(suffix)
	if err != nil || bits < 0 || bits > 32 {
		err = fmt.Errorf(errInvalidCIDRFmt, cidr)
		return
	}

	mask = uint32(0xffffffff) << uint32(32-bits)
	prefix = ip & mask
	return
}

// ToOctets converts a 32-bit unsigned integer into a readable string in "*.*.*.*" format.
func ToOctets(ip uint32) string {
	octets := []string{}
	for ip > 0 {
		octet := fmt.Sprint(ip % 256)
		octets = append([]string{octet}, octets...)
		ip >>= 8
	}
	return strings.Join(octets, ".")
}

// InAddressSpace checks if an IP address is part of the address space defined by a CIDR notation
func InAddressSpace(ipAddr string, cidr string) (result bool, err error) {
	ip, err := ParseIPAddress(ipAddr)
	if err != nil {
		return
	}

	prefix, mask, err := ParseCIDR(cidr)
	if err != nil {
		return
	}

	result = (ip & mask) == prefix
	return
}
