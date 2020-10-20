package filterutil

import (
	"encoding/binary"
	"errors"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
)

// ExtractHostname -- quickly retrieves hostname from an URL
func ExtractHostname(url string) string {
	if url == "" {
		return ""
	}

	firstIdx := strings.Index(url, "//")
	if firstIdx == -1 {
		// This is a non hierarchical structured URL (e.g. stun: or turn:)
		// https://tools.ietf.org/html/rfc4395#section-2.2
		// https://tools.ietf.org/html/draft-nandakumar-rtcweb-stun-uri-08#appendix-B
		firstIdx = strings.Index(url, ":")
		if firstIdx == -1 {
			return ""
		}
		firstIdx = firstIdx - 1
	} else {
		firstIdx = firstIdx + 2
	}

	nextIdx := 0
	for i := firstIdx; i < len(url); i++ {
		c := url[i]
		if c == '/' || c == ':' || c == '?' {
			nextIdx = i
			break
		}
	}

	if nextIdx == 0 {
		nextIdx = len(url)
	}

	if nextIdx <= firstIdx {
		return ""
	}

	return url[firstIdx:nextIdx]
}

// IsDomainName - check if input string is a valid domain name
// Syntax: [label.]... label.label
//
// Each label is 1 to 63 characters long, and may contain:
//   . ASCII letters a-z and A-Z
//   . digits 0-9
//   . hyphen ('-')
// . labels cannot start or end with hyphens (RFC 952)
// . max length of ascii hostname including dots is 253 characters
// . TLD is >=2 characters
// . TLD is [a-zA-Z]+ or "xn--[a-zA-Z0-9]+"
// . at least 1 level above TLD Source
// nolint(gocyclo)
func IsDomainName(name string) bool {
	if len(name) > 253 {
		return false
	}

	st := 0
	nLabel := 0
	nLevel := 1
	var prevChar byte
	charOnly := true
	xn := 0

	for _, c := range []byte(name) {

		switch st {
		case 0:
			fallthrough
		case 1:
			if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z')) {
				charOnly = false
				if !(c >= '0' && c <= '9') {
					return false
				}
			} else if c == 'x' || c == 'X' {
				xn = 1
			}
			st = 2
			nLabel = 1

		case 2:
			if c == '.' {
				if prevChar == '-' {
					return false
				}
				nLevel++
				st = 0
				charOnly = true
				xn = 0
				continue
			}

			if nLabel == 63 {
				return false
			}

			if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z')) {
				charOnly = false
				if !((c >= '0' && c <= '9') ||
					c == '-') {
					return false
				}
			}

			if xn > 0 {
				if xn < len("xn--") {
					if c == "xn--"[xn] {
						xn++
					} else {
						xn = 0
					}
				} else {
					xn++
				}
			}

			prevChar = c
			nLabel++
		}
	}

	if st != 2 ||
		nLabel == 1 ||
		nLevel == 1 ||
		(!charOnly && xn < len("xn--wwww")) {
		return false
	}

	return true
}

var cidrToMask = []uint32{
	0x00000000, 0x80000000, 0xC0000000,
	0xE0000000, 0xF0000000, 0xF8000000,
	0xFC000000, 0xFE000000, 0xFF000000,
	0xFF800000, 0xFFC00000, 0xFFE00000,
	0xFFF00000, 0xFFF80000, 0xFFFC0000,
	0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
	0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
	0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
	0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
	0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
	0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
}

// IPv4RangeToCIDR -- creates a IPv4 CIDR range from two ips
func IPv4RangeToCIDR(start, end net.IP) ([]net.IPNet, error) {
	startAddr, err := IPv4ToLong(start)
	if err != nil {
		log.Fatalf(err.Error())
	}
	endAddr, err := IPv4ToLong(end)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if startAddr > endAddr {
		return []net.IPNet{}, errors.New("start of IP range must be less than the end")
	}

	var cidrList []net.IPNet

	for i := endAddr; i >= startAddr; i-- {
		maxSize := 32
		for j := maxSize; j > 0; j-- {
			mask := cidrToMask[maxSize-1]
			maskedBase := startAddr & mask

			if maskedBase != startAddr {
				break
			}

			maxSize--
		}

		x := math.Log(float64(endAddr-startAddr+1)) / math.Log(2)
		maxDiff := int(32) - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		_, n, _ := net.ParseCIDR(LongToIPv4(startAddr) + "/" + strconv.Itoa(maxSize))

		cidrList = append(cidrList, *n)

		startAddr += uint32(math.Pow(2, float64(32-maxSize)))
	}
	return cidrList, nil
}

// IPv4ToLong -- creates a long from a IPv4
func IPv4ToLong(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, errors.New("ip must be a ipv4 address")
	}
	return binary.BigEndian.Uint32(ip), nil
}

// LongToIPv4 -- creates a IPv4 from a long
func LongToIPv4(ipl uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipl)
	ip := net.IP(ipb)
	return ip.String()
}
