// +build linux

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bandwidth

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/exec"

	"k8s.io/klog"
)

const (
	// tcFilterIPv4Protocol represents tc filter protocol for IPv4
	tcFilterIPv4Protocol = "ip"
	// tcFilterIPv6Protocol represents tc filter protocol for IPv6
	tcFilterIPv6Protocol = "ipv6"
	// tcFilterIPv4Priority represents tc filter priority for IPv4
	tcFilterIPv4Priority = "1"
	// tcFilterIPv6Priority represents tc filter priority for IPv6
	tcFilterIPv6Priority = "2"
	// u32MatchIPv4Protocol represents tc u32 filter protocol for IPv4
	u32MatchIPv4Protocol = "ip"
	// u32MatchIPv6Protocol represents tc u32 filter protocol for IPv6
	u32MatchIPv6Protocol = "ip6"

	// maxRowOfMatchLinePerIPv6CIDR represents the max rows of match lines per IPv6 cidr in `tc filter show dev xxx` output
	maxRowOfMatchLinePerIPv6CIDR = 4
	// hexCIDR8ZeroPadding is used to append padding when restore IPv6 store from tc filter match lines
	hexCIDR8ZeroPadding = "00000000"
	// hexCIDRZeroIPv6 is all zero IPv6 hex CIDR
	hexCIDRZeroIPv6 = "00000000000000000000000000000000/00000000000000000000000000000000"
)

var (
	// classShowMatcher is used to extract classID from `tc class show dev xxx` output.
	// e.g. class htb 1:10 root prio 0 rate 8Gbit ceil 8Gbit burst 0b cburst 0b
	classShowMatcher = regexp.MustCompile(`class htb (1:\d+)`)
	// classAndHandleIPv4Matcher is used to extract classID and handle for IPv4 CIDR from `tc filter show dev xxx` output.
	// e.g. filter parent 1: protocol ip pref 1 u32 fh 801::800 order 2048 key ht 801 bkt 0 flowid 1:1
	classAndHandleIPv4Matcher = regexp.MustCompile(`filter parent 1: protocol ip .*fh (\d+::\d+).*flowid (\d+:\d+)`)
	// classAndHandleIPv6Matcher is used to extract classID and handle for IPv6 CIDR from `tc filter show dev xxx` output.
	// e.g. filter parent 1: protocol ipv6 pref 2 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
	classAndHandleIPv6Matcher = regexp.MustCompile(`filter parent 1: protocol ipv6 .*fh (\d+::\d+).*flowid (\d+:\d+)`)
)

// tcShaper provides an implementation of the Shaper interface on Linux using the 'tc' tool.
// In general, using this requires that the caller posses the NET_CAP_ADMIN capability, though if you
// do this within an container, it only requires the NS_CAPABLE capability for manipulations to that
// container's network namespace.
// Uses the hierarchical token bucket queuing discipline (htb), this requires Linux 2.4.20 or newer
// or a custom kernel with that queuing discipline backported.
type tcShaper struct {
	e     exec.Interface
	iface string
}

// NewTCShaper makes a new tcShaper for the given interface
func NewTCShaper(iface string) Shaper {
	shaper := &tcShaper{
		e:     exec.New(),
		iface: iface,
	}
	return shaper
}

func (t *tcShaper) execAndLog(cmdStr string, args ...string) error {
	klog.V(6).Infof("Running: %s %s", cmdStr, strings.Join(args, " "))
	cmd := t.e.Command(cmdStr, args...)
	out, err := cmd.CombinedOutput()
	klog.V(6).Infof("Output from tc: %s", string(out))
	return err
}

func (t *tcShaper) nextClassID() (int, error) {
	data, err := t.e.Command("tc", "class", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return -1, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	classes := sets.String{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip empty lines
		if len(line) == 0 {
			continue
		}
		// expected tc line:
		// class htb 1:1 root prio 0 rate 1000Kbit ceil 1000Kbit burst 1600b cburst 1600b
		matches := classShowMatcher.FindStringSubmatch(line)
		if len(matches) != 2 {
			return -1, fmt.Errorf("unexpected output from tc: %s (%v)", scanner.Text(), matches)
		}
		classes.Insert(matches[1])
	}

	// Make sure it doesn't go forever
	for nextClass := 1; nextClass < 10000; nextClass++ {
		if !classes.Has(fmt.Sprintf("1:%d", nextClass)) {
			return nextClass, nil
		}
	}
	// This should really never happen
	return -1, fmt.Errorf("exhausted class space, please try again")
}

// Convert a CIDR from text to a hex representation
// Strips any masked parts of the IP, so 1.2.3.4/16 becomes hex(1.2.0.0)/ffffffff
func hexCIDR(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip = ip.Mask(ipnet.Mask)
	hexIP := hex.EncodeToString([]byte(ip))
	hexMask := ipnet.Mask.String()
	return hexIP + "/" + hexMask, nil
}

// Convert a CIDR from hex representation to text, opposite of the above.
func asciiCIDR(cidr string) (string, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected CIDR format: %s", cidr)
	}
	ipData, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ip := net.IP(ipData)

	maskData, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	mask := net.IPMask(maskData)
	size, _ := mask.Size()

	return fmt.Sprintf("%s/%d", ip.String(), size), nil
}

// isIPv6CIDRString uses a tricky way to judge whether a CIDR is IPv6 or not.
// For CIDR like `::ffff:1.2.3.4/128`, golang's stdlib will treat it as an IPv4 address, while tc uses IPv6 filter and matcher.
func isIPv6CIDRString(cidr string) bool {
	return strings.Count(cidr, ":") >= 2
}

func (t *tcShaper) findCIDRClass(cidr string) (classAndHandleList [][]string, found bool, err error) {
	data, err := t.e.Command("tc", "filter", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return classAndHandleList, false, err
	}

	hex, err := hexCIDR(cidr)
	if err != nil {
		return classAndHandleList, false, err
	}

	if isIPv6CIDRString(cidr) {
		return t.findIPv6CIDRClass(hex, data)
	}
	return t.findIPv4CIDRClass(hex, data)
}

func (t *tcShaper) findIPv4CIDRClass(hexCIDR string, cmdOutput []byte) (classAndHandleList [][]string, found bool, err error) {
	spec := fmt.Sprintf("match %s", hexCIDR)
	outputLines := convertByteSliceToStringSlice(cmdOutput)

	scanner := newLimitRuleScanner(outputLines, false)
	for scanner.scanLimitRule() {
		matchLines := scanner.matchLines()
		// IPv4 only have just one match line
		if len(matchLines) != 1 {
			return classAndHandleList, false, fmt.Errorf("unexpected output: %v", matchLines)
		}

		if strings.Contains(matchLines[0], spec) {
			// expected tc line:
			// `filter parent 1: protocol ip pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1` (old version) or
			// `filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1 not_in_hw` (new version)
			matches := classAndHandleIPv4Matcher.FindStringSubmatch(scanner.flowidLine())
			if len(matches) != 3 {
				return classAndHandleList, false, fmt.Errorf("unexpected output from tc: %s %d (%v)", scanner.flowidLine(), len(matches), matches)
			}
			resultTmp := []string{matches[2], matches[1]}
			classAndHandleList = append(classAndHandleList, resultTmp)
		}
	}
	if len(classAndHandleList) > 0 {
		return classAndHandleList, true, nil
	}
	return classAndHandleList, false, nil
}

func (t *tcShaper) findIPv6CIDRClass(hexCIDR string, cmdOutput []byte) (classAndHandleList [][]string, found bool, err error) {
	outputLines := convertByteSliceToStringSlice(cmdOutput)

	scanner := newLimitRuleScanner(outputLines, true)
	for scanner.scanLimitRule() {
		matchLines := scanner.matchLines()

		// restore hex cidr from match lines
		restoreCIDR, err := restoreIPv6HexCIDR(matchLines)
		if err != nil {
			return classAndHandleList, false, err
		}

		if restoreCIDR == hexCIDR {
			matches := classAndHandleIPv6Matcher.FindStringSubmatch(scanner.flowidLine())
			if len(matches) != 3 {
				return classAndHandleList, false, fmt.Errorf("unexpected output from tc: %s %d (%v)", scanner.flowidLine(), len(matches), matches)
			}
			resultTmp := []string{matches[2], matches[1]}
			classAndHandleList = append(classAndHandleList, resultTmp)
		}
	}
	if len(classAndHandleList) > 0 {
		return classAndHandleList, true, nil
	}
	return classAndHandleList, false, nil
}

// restoreIPv6HexCIDR restores IPv6 CIDR from match lines of tc filter output
func restoreIPv6HexCIDR(matchLines []string) (string, error) {
	if len(matchLines) > maxRowOfMatchLinePerIPv6CIDR {
		return "", fmt.Errorf("unexpected output: %v", matchLines)
	}
	// for all zero IPv6 CIDR "::/0", tc does not output any match line.
	if len(matchLines) == 0 {
		return hexCIDRZeroIPv6, nil
	}

	var ipv6Address, ipv6Mask string
	for _, line := range matchLines {
		parts := strings.Split(line, " ")
		// expected line:
		// match <cidr> at <number>
		if len(parts) != 4 {
			return "", fmt.Errorf("unexpected output: %v", parts)
		}

		ipAndMaskParts := strings.Split(parts[1], "/")
		if len(ipAndMaskParts) != 2 {
			return "", fmt.Errorf("unexpected output: %v", parts)
		}
		ipv6Address += ipAndMaskParts[0]
		ipv6Mask += ipAndMaskParts[1]
	}

	// append 8-zero padding for small CIDR mask size condition
	rowShort := maxRowOfMatchLinePerIPv6CIDR - len(matchLines)
	for i := 0; i < rowShort; i++ {
		ipv6Address += hexCIDR8ZeroPadding
		ipv6Mask += hexCIDR8ZeroPadding
	}

	return fmt.Sprintf("%s/%s", ipv6Address, ipv6Mask), nil
}

func makeKBitString(rsrc *resource.Quantity) string {
	return fmt.Sprintf("%dkbit", (rsrc.Value() / 1000))
}

func (t *tcShaper) makeNewClass(rate string) (int, error) {
	class, err := t.nextClassID()
	if err != nil {
		return -1, err
	}
	if err := t.execAndLog("tc", "class", "add",
		"dev", t.iface,
		"parent", "1:",
		"classid", fmt.Sprintf("1:%d", class),
		"htb", "rate", rate); err != nil {
		return -1, err
	}
	return class, nil
}

func (t *tcShaper) Limit(cidr string, upload, download *resource.Quantity) (err error) {
	if isIPv6CIDRString(cidr) {
		return t.limit(cidr, upload, download, tcFilterIPv6Protocol, tcFilterIPv6Priority, u32MatchIPv6Protocol)
	}
	return t.limit(cidr, upload, download, tcFilterIPv4Protocol, tcFilterIPv4Priority, u32MatchIPv4Protocol)
}

func (t *tcShaper) limit(cidr string, upload, download *resource.Quantity, tcProtocol, priority, matchProtocol string) (err error) {
	var downloadClass, uploadClass int
	if download != nil {
		if downloadClass, err = t.makeNewClass(makeKBitString(download)); err != nil {
			return err
		}
		if err := t.execAndLog("tc", "filter", "add",
			"dev", t.iface,
			"protocol", tcProtocol,
			"parent", "1:0",
			"prio", priority, "u32",
			"match", matchProtocol, "dst", cidr,
			"flowid", fmt.Sprintf("1:%d", downloadClass)); err != nil {
			return err
		}
	}
	if upload != nil {
		if uploadClass, err = t.makeNewClass(makeKBitString(upload)); err != nil {
			return err
		}
		if err := t.execAndLog("tc", "filter", "add",
			"dev", t.iface,
			"protocol", tcProtocol,
			"parent", "1:0",
			"prio", priority, "u32",
			"match", matchProtocol, "src", cidr,
			"flowid", fmt.Sprintf("1:%d", uploadClass)); err != nil {
			return err
		}
	}
	return nil
}

// tests to see if an interface exists, if it does, return true and the status line for the interface
// returns false, "", <err> if an error occurs.
func (t *tcShaper) interfaceExists() (bool, string, error) {
	data, err := t.e.Command("tc", "qdisc", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return false, "", err
	}
	value := strings.TrimSpace(string(data))
	if len(value) == 0 {
		return false, "", nil
	}
	// Newer versions of tc and/or the kernel return the following instead of nothing:
	// qdisc noqueue 0: root refcnt 2
	fields := strings.Fields(value)
	if len(fields) > 1 && fields[1] == "noqueue" {
		return false, "", nil
	}
	return true, value, nil
}

func (t *tcShaper) ReconcileCIDR(cidr string, upload, download *resource.Quantity) error {
	_, found, err := t.findCIDRClass(cidr)
	if err != nil {
		return err
	}
	if !found {
		return t.Limit(cidr, upload, download)
	}
	// TODO: actually check bandwidth limits here
	return nil
}

func (t *tcShaper) ReconcileInterface() error {
	exists, output, err := t.interfaceExists()
	if err != nil {
		return err
	}
	if !exists {
		klog.V(4).Info("Didn't find bandwidth interface, creating")
		return t.initializeInterface()
	}
	// expected output:
	// qdisc htb 1: root refcnt 2 r2q 10 default 0x30 direct_packets_stat 86 direct_qlen 1000
	fields := strings.Split(output, " ")
	if len(fields) < 12 || fields[1] != "htb" || fields[2] != "1:" {
		if err := t.deleteInterface(fields[2]); err != nil && !noSuchQdisc(err) {
			return err
		}
		return t.initializeInterface()
	}
	return nil
}

func (t *tcShaper) initializeInterface() error {
	return t.execAndLog("tc", "qdisc", "add", "dev", t.iface, "root", "handle", "1:", "htb", "default", "30")
}

func (t *tcShaper) Reset(cidr string) error {
	classAndHandle, found, err := t.findCIDRClass(cidr)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("Failed to find cidr: %s on interface: %s", cidr, t.iface)
	}
	for i := 0; i < len(classAndHandle); i++ {
		if err := t.execAndLog("tc", "filter", "del",
			"dev", t.iface,
			"parent", "1:",
			"proto", "ip",
			"prio", "1",
			"handle", classAndHandle[i][1], "u32"); err != nil {
			return err
		}
		if err := t.execAndLog("tc", "class", "del",
			"dev", t.iface,
			"parent", "1:",
			"classid", classAndHandle[i][0]); err != nil {
			return err
		}
	}
	return nil
}

func (t *tcShaper) deleteInterface(class string) error {
	return t.execAndLog("tc", "qdisc", "delete", "dev", t.iface, "root", "handle", class)
}

func (t *tcShaper) GetCIDRs() ([]string, error) {
	data, err := t.e.Command("tc", "filter", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return nil, err
	}

	result := []string{}
	outputLines := convertByteSliceToStringSlice(data)

	ipv4Result, err := t.getIPv4CIDRs(outputLines)
	if err != nil {
		return nil, err
	}

	ipv6Result, err := t.getIPv6CIDRs(outputLines)
	if err != nil {
		return nil, err
	}

	result = append(result, ipv4Result...)
	result = append(result, ipv6Result...)

	return result, nil
}

func (t *tcShaper) getIPv4CIDRs(outputLines []string) ([]string, error) {
	result := []string{}

	scanner := newLimitRuleScanner(outputLines, false)
	for scanner.scanLimitRule() {
		matchLines := scanner.matchLines()
		// IPv4 only have just one match line
		if len(matchLines) != 1 {
			return nil, fmt.Errorf("unexpected output: %v", matchLines)
		}
		parts := strings.Split(matchLines[0], " ")
		// expected tc line:
		// match <cidr> at <number>
		if len(parts) != 4 {
			return nil, fmt.Errorf("unexpected output: %v", parts)
		}
		cidr, err := asciiCIDR(parts[1])
		if err != nil {
			return nil, err
		}
		result = append(result, cidr)
	}

	return result, nil
}

func (t *tcShaper) getIPv6CIDRs(outputLines []string) ([]string, error) {
	result := []string{}

	scanner := newLimitRuleScanner(outputLines, true)
	for scanner.scanLimitRule() {
		matchLines := scanner.matchLines()
		// restore hex cidr from match lines
		restoreCIDR, err := restoreIPv6HexCIDR(matchLines)
		if err != nil {
			return nil, err
		}
		cidr, err := asciiCIDR(restoreCIDR)
		if err != nil {
			return nil, err
		}
		result = append(result, cidr)
	}

	return result, nil
}

// isFilterMatchLine returns whether a line is in the format of `match <cidr> at <number>`
func isFilterMatchLine(line string) bool {
	return strings.Contains(line, "match")
}

// isFilterFlowidLine returns whether a line is in the format of `filter parent 1: protocol <protocol> pref <prio> u32 fh <handle> order <order> key ht <major> bkt <num> flowid <classid>`
func isFilterFlowidLine(line string, wantIPv6 bool) bool {
	var matches []string
	if wantIPv6 {
		matches = classAndHandleIPv6Matcher.FindStringSubmatch(line)
	} else {
		matches = classAndHandleIPv4Matcher.FindStringSubmatch(line)
	}
	if len(matches) != 3 {
		return false
	}
	return true
}

// limitRuleScanner provides a convenient interface to get data from `tc filter show dev xxx` output.
// Successive calls to the scanLimitRule method will step to the next limit rule. A limit rule consists of a flowid line and match lines(s).
// limitRuleScanner supports both IPv4 and IPv6 limit rule. An IPv4 limit rule has only one match line, while an IPv6 limit rule can have 0-4 match lines.
// A typical IPv4 limit rule as below:
// filter parent 1: protocol ip pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
//  match ac110002/ffffffff at 16
// A typical IPv6 limit rule as below:
// filter parent 1: protocol ipv6 pref 2 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
//  match 20010da8/ffffffff at 24
//  match 80006023/ffffffff at 28
//  match 00000000/ffffffff at 32
//  match 00000230/ffffffff at 36
type limitRuleScanner struct {
	tcOutput      []string // the output lines of `tc filter show dev xxx`
	wantIPv6      bool     // scanLimitRule IPv4 or IPv6
	idx           int      // index of current line being scanned in the tcOutput
	flowidLineIdx int      // index of current flowid line in the tcOutput
	matchlines    []string // current match lines
}

// newLimitRuleScanner returns a new limitRuleScanner
func newLimitRuleScanner(cmdOutput []string, wantIPv6 bool) *limitRuleScanner {
	return &limitRuleScanner{
		tcOutput: cmdOutput,
		wantIPv6: wantIPv6,
	}
}

// scanLimitRule advances the limitRuleScanner to the next limit rule, which will then be able to call matchLines and flowidLine methods.
// It returns false when limitRuleScanner reaches the end of the command output.
func (s *limitRuleScanner) scanLimitRule() bool {
	for s.idx < len(s.tcOutput) {
		if !isFilterFlowidLine(s.tcOutput[s.idx], s.wantIPv6) {
			s.idx++
			continue
		}

		// find the most recent flowid line
		s.flowidLineIdx = s.idx
		nextFlowidIdx := s.idx + 1
		// skip match lines, continue to find the next most recent flowid line
		for nextFlowidIdx < len(s.tcOutput) {
			if !isFilterMatchLine(s.tcOutput[nextFlowidIdx]) {
				break
			}
			nextFlowidIdx++
		}

		// match lines are between two flowid lines
		s.matchlines = s.tcOutput[s.idx+1 : nextFlowidIdx]
		s.idx = nextFlowidIdx
		return true
	}
	return false
}

// matchLines returns the most recent match lines found by a call to scanLimitRule.
func (s *limitRuleScanner) matchLines() []string {
	return s.matchlines
}

// flowidLine returns the most recent flowid line found by a call to scanLimitRule.
func (s *limitRuleScanner) flowidLine() string {
	return s.tcOutput[s.flowidLineIdx]
}

func convertByteSliceToStringSlice(data []byte) []string {
	lines := []string{}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		lines = append(lines, line)
	}

	return lines
}

func noSuchQdisc(err error) bool {
	if exitErr, ok := err.(*exec.ExitErrorWrapper); ok {
		return exitErr.ExitCode() == 0x2
	}
	return false
}
