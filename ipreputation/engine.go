package ipreputation

import (
	"azwaf/waf"
	"strconv"
	"strings"
	"sync"
)

// IPv4 addresses are composed of 4 separate 8-bit integers
const ipSize = 32

const badBotsfileName = "badbots.txt"

type engineImpl struct {
	ipMatcher  *binaryTrie
	writeMutex sync.Mutex
	fs         fileSystem
}

// NewIPReputationEngine creates a engine for determining an ip's reputation
func NewIPReputationEngine(fs fileSystem) waf.IPReputationEngine {
	e := &engineImpl{fs: fs}
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

func (e *engineImpl) EvalRequest(req waf.HTTPRequest) bool {
	isMatch := e.ipMatcher.match(req.RemoteAddr())
	return isMatch
}

func (e *engineImpl) readFromDisk(fileName string) (ips []string) {
	data, err := e.fs.readFile(fileName)
	if err != nil {
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
	e.fs.writeFile(fileName, data)
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
		ipInt, mask := extractIPAndMask(ip)
		node := t.root
		var i uint
		depth := 0

		for i = 0; i <= ipSize; i++ {
			if node.isMatch() {
				break
			}
			if depth == mask {
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
			depth++
		}
	}
}

func (t *binaryTrie) match(ip string) bool {
	numbers := strings.Split(ip, ".")
	node := t.root

	ipInt := toIPInt(numbers)
	var i uint
	for i = 0; i < ipSize; i++ {
		isMatch := node.isMatch()
		if isMatch {
			return isMatch
		}

		curBit := getBitAtIndex(ipInt, i)
		if curBit == 1 {
			node = node.getOne()
		} else {
			node = node.getZero()
		}
		if node == nil {
			return false
		}
	}

	return node.isMatch()
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

// Takes the 4 numbers and inserts them at the 24th, 16th, 8th and 0th bit respectively
func toIPInt(numbers []string) int {
	var ipInt int
	numCount := 4
	numSize := 8
	for i := 0; i < numCount; i++ {
		num, _ := strconv.Atoi(numbers[i])
		ipInt |= num << uint(numSize*(numCount-1-i))
	}
	return ipInt
}

func extractIPAndMask(ip string) (ipInt int, mask int) {
	split := strings.Split(ip, "/")
	numbers := strings.Split(split[0], ".")
	ipInt = toIPInt(numbers)

	if len(split) == 2 {
		maskString := split[1]
		mask, _ = strconv.Atoi(maskString)
	} else {
		// If there's no mask, default its value to 32
		mask = 32
	}
	return
}

// Returns the value of the bit at index i
func getBitAtIndex(num int, index uint) (curBit int) {
	curBit = (num >> (ipSize - 1 - index)) & 1
	return
}
