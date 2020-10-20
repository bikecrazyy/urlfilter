package rules

import (
	"errors"
	"net"
	"regexp"

	// "github.com/bikecrazyy/urlfilter/filterutil"
	"github.com/bikecrazyy/urlfilter/filterutil"

	"github.com/yl2chen/cidranger"
)

type IPFilterRanger struct {
	listID int
	hash   string
	ranger cidranger.Ranger
}

type IPRule struct {
	RuleText     string      // RuleText is the original rule text
	FilterListID int         // Filter list identifier
	IPNet        []net.IPNet // ip address
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *IPRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *IPRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *IPRule) String() string {
	return f.RuleText
}

// IPEngine is the engine that supports quick search over ip rules
type IPEngine struct {
	RulesCount  int     // RulesCount -- count of rules added to the engine
	ruleStorage *IPRule // Storage for the network filtering rules
	IPRangers   map[int]IPFilterRanger
}

// Match checks if this filtering rule matches the specified hostname
func (e *IPEngine) Match(hostname string) (*IPRule, bool) {
	for _, r := range e.IPRangers {
		return &IPRule{
			RuleText:     "",
			FilterListID: r.listID,
			IPNet:        []net.IPNet{},
		}, true
	}
	return &IPRule{}, true
}

// AddRule adds rule to the IPEngine
func (e *IPEngine) AddRule(r *IPRule) {
	listID := r.GetFilterListID()

	_, exists := e.IPRangers[listID]
	if !exists {
		e.IPRangers[listID] = IPFilterRanger{ranger: cidranger.NewPCTrieRanger()}
	}

	e.RulesCount++

	for _, in := range r.IPNet {
		e.IPRangers[listID].ranger.Insert(cidranger.NewBasicRangerEntry(in))
	}
}

// NewIPRule created a new IP Rule from filter list line
func NewIPRule(line string, filterListID int) (*IPRule, error) {
	// todo: check line to see if rule can be parsed
	cidrs, err := IPParser(line)

	if cidrs == nil {
		return nil, err
	}

	r := IPRule{
		RuleText:     line,
		FilterListID: filterListID,
		IPNet:        cidrs,
	}

	return &r, nil
}

// Parse to find ip supported patterns
func IPParser(pattern string) ([]net.IPNet, error) {
	// match single IP (192.168.0.100)
	ip := net.ParseIP(pattern)

	if ip != nil {
		if ip.To4() != nil {
			// if ipv4
			_, ipNet, err := net.ParseCIDR(ip.String() + "::/64")

			if err != nil {
				return nil, err
			}
			return []net.IPNet{*ipNet}, nil
		} else if ip.To16() != nil {
			// if ipv6
			_, ipNet, err := net.ParseCIDR(ip.String() + "/32")

			if err != nil {
				return nil, err
			}
			return []net.IPNet{*ipNet}, nil
		}
	}

	// match cidr (192.168.0.1/32)
	_, ipCIDR, err := net.ParseCIDR(pattern)

	if err != nil {
		return []net.IPNet{*ipCIDR}, nil
	}

	// match iblocklist.com ip pattern( Example site:10.0.1.100-10.0.1.120 )
	itemList := regexp.MustCompile("^(.*?):(.*?)-(.*?)$").Split(pattern, -1)

	if len(itemList) == 3 {
		ipStart := net.ParseIP(itemList[1])
		ipEnd := net.ParseIP(itemList[2])

		if ipStart.To4() != nil && ipEnd.To4() != nil {
			return filterutil.IPv4RangeToCIDR(ipStart, ipEnd)
		}
	}

	// match ipv4 range( 10.0.1.100-10.0.1.120 )
	itemList = regexp.MustCompile("^(.*?)-(.*?)$").Split(pattern, -1)

	if len(itemList) == 2 {
		ipStart := net.ParseIP(itemList[0])
		ipEnd := net.ParseIP(itemList[1])

		if ipStart.To4() != nil && ipEnd.To4() != nil {
			return filterutil.IPv4RangeToCIDR(ipStart, ipEnd)
		}
	}

	return nil, errors.New("unable to parser, not matches found")
}
