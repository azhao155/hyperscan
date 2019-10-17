package ipreputation

import (
	"azwaf/ipaddresses"
	"azwaf/waf"
	"strconv"
	"strings"
	"sync"
)

// IPv4 addresses are composed of 4 separate 8-bit integers
const ipSize = 32

const badBotsfileName = "badbots.txt"
const xForwardedForHeaderName = "X-Forwarded-For"

type engineImpl struct {
	ipMatcher     *binaryTrie
	writeMutex    sync.Mutex
	fs            FileSystem
	resultsLogger ResultsLogger
}

// NewIPReputationEngine creates a engine for determining an ip's reputation
func NewIPReputationEngine(fs FileSystem, resultsLogger ResultsLogger) waf.IPReputationEngine {
	e := &engineImpl{fs: fs, resultsLogger: resultsLogger}
	ips := e.readFromDisk(badBotsfileName)
	e.ipMatcher = newBinaryTrie(ips)
	return e
}

func (e *engineImpl) PutIPReputationList(ips []string) {
	e.writeMutex.Lock()
	defer e.writeMutex.Unlock()
	e.writeToDisk(badBotsfileName, ips)
	e.ipMatcher = newBinaryTrie(ips)
}

func (e *engineImpl) EvalRequest(req waf.IPReputationEngineHTTPRequest) waf.Decision {
	var ips []string
	for _, header := range req.Headers() {
		if strings.EqualFold(header.Key(), xForwardedForHeaderName) {
			ips = parseXForwardedForHeaderIps(header.Value())
		}
	}
	ips = append(ips, req.RemoteAddr())

	for _, ip := range ips {
		isMatch, err := e.ipMatcher.match(ip)
		if err != nil {
			e.resultsLogger.IPReputationTriggered(req)
			return waf.Block
		}
		// TO DO: replace return waf.Block with config-specified action
		if isMatch {
			e.resultsLogger.IPReputationTriggered(req)
			return waf.Block
		}
	}

	return waf.Pass
}

func parseXForwardedForHeaderIps(header string) []string {
	ips := strings.Split(header, ",")
	for index, ip := range ips {
		ip = strings.TrimSpace(ip)
		ip = stripPortFromIP(ip)
		ips[index] = ip
	}
	return ips
}

func stripPortFromIP(ipWithPort string) string {
	ipAndPort := strings.Split(ipWithPort, ":")
	return ipAndPort[0]
}

func (e *engineImpl) readFromDisk(fileName string) (ips []string) {
	data, err := e.fs.ReadFile(fileName)
	if err != nil || data == nil {
		ips = make([]string, 0)
	} else {
		content := string(data)
		ips = strings.Split(content, "\n")
	}
	return
}

func (e *engineImpl) writeToDisk(fileName string, ips []string) {
	content := strings.Join(ips, "\n")
	data := []byte(content)
	e.fs.WriteFile(fileName, data)
}

type binaryTrie struct {
	root *nodeImpl
}

func newBinaryTrie(ips []string) (t *binaryTrie) {
	t = &binaryTrie{root: newNode()}
	t.populate(ips)
	return
}

func (t *binaryTrie) clear() {
	t.root = newNode()
}

func (t *binaryTrie) populate(ips []string) {
	for _, ip := range ips {
		ipInt, mask := parseIP(ip)
		node := t.root
		var i uint

		for i = 0; i <= ipSize; i++ {
			if node.isMatch() {
				break
			}
			if i == mask {
				node.setMatch()
				break
			}

			curBit := getBitAtIndex(ipInt, i)
			var child *nodeImpl
			if curBit == 0 {
				child = node.getZero()
				if child == nil {
					child = node.setZero()
				}
			} else {
				child = node.getOne()
				if child == nil {
					child = node.setOne()
				}
			}
			node = child
		}
	}
}

func (t *binaryTrie) match(ip string) (isMatch bool, err error) {
	node := t.root

	ipInt, err := ipaddresses.ParseIPAddress(ip)
	var i uint
	for i = 0; i < ipSize; i++ {
		isMatch = node.isMatch()
		if isMatch {
			return
		}

		curBit := getBitAtIndex(ipInt, i)
		if curBit == 1 {
			node = node.getOne()
		} else {
			node = node.getZero()
		}
		if node == nil {
			isMatch = false
			return
		}
	}
	isMatch = node.isMatch()
	return
}

type nodeImpl struct {
	match bool
	one   *nodeImpl
	zero  *nodeImpl
}

func newNode() *nodeImpl {
	return &nodeImpl{}
}

func (n *nodeImpl) getOne() *nodeImpl {
	return n.one
}

func (n *nodeImpl) setOne() *nodeImpl {
	n.one = newNode()
	return n.one
}

func (n *nodeImpl) getZero() *nodeImpl {
	return n.zero
}

func (n *nodeImpl) setZero() *nodeImpl {
	n.zero = newNode()
	return n.zero
}

func (n *nodeImpl) isMatch() bool {
	return n.match
}

func (n *nodeImpl) setMatch() {
	n.match = true
}

func parseIP(ip string) (ipInt uint32, mask uint) {
	split := strings.Split(ip, "/")
	ipInt, _ = ipaddresses.ParseIPAddress(split[0])

	if len(split) == 2 {
		maskString := split[1]
		maskNumber, _ := strconv.Atoi(maskString)
		mask = uint(maskNumber)
	} else {
		// If there's no mask, default its value to 32
		mask = 32
	}
	return
}

// Returns the value of the bit at index i
func getBitAtIndex(num uint32, index uint) (curBit uint32) {
	curBit = (num >> (ipSize - 1 - index)) & 1
	return
}
