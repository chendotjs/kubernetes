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
	maxRowOfMatchLinePerIPv6CIDR = 4
	hexCIDR8ZeroPadding          = "00000000"
	hexCIDRZeroIPv6              = "00000000000000000000000000000000/00000000000000000000000000000000"

	tcFilterIPv4Protocol = "ip"
	tcFilterIPv6Protocol = "ipv6"
	tcFilterIPv4Priority = "1"
	tcFilterIPv6Priority = "2"
	u32MatchIPv4Protocol = "ip"
	u32MatchIPv6Protocol = "ip6"
)

var (
	classShowMatcher          = regexp.MustCompile(`class htb (1:\d+)`)
	classAndHandleIPv4Matcher = regexp.MustCompile(`filter parent 1: protocol ip .*fh (\d+::\d+).*flowid (\d+:\d+)`)
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

	scanner := bufio.NewScanner(bytes.NewBuffer(cmdOutput))
	filter := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "filter") {
			filter = line
			continue
		}
		if strings.Contains(line, spec) {
			// expected tc line:
			// `filter parent 1: protocol ip pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1` (old version) or
			// `filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1 not_in_hw` (new version)
			matches := classAndHandleIPv4Matcher.FindStringSubmatch(filter)
			if len(matches) != 3 {
				continue
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

	// Since the match line num of `tc filter show dev xxx` output varies from 0 to 4 for IPv6 cidr,
	// slow and fast are two indexes that indicate the range of match lines in the output.
	// When slow finds a flowid line, fast continues to search for the succeeding flowid line or end of output from the position of slow.
	var slow, fast int = 0, 0
	for slow < len(outputLines) {
		matches := classAndHandleIPv6Matcher.FindStringSubmatch(outputLines[slow])
		if len(matches) != 3 {
			slow++
			continue
		}
		// expected outputLines[slow]:
		// filter parent 1: protocol ipv6 pref 2 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
		fast = slow + 1
		for fast < len(outputLines) {
			if !isFilterMatchLine(outputLines[fast]) {
				break
			}
			fast++
		}
		// e.g. outputMatchLines:
		// [match 20010db8/ffffffff at 8 match 86a308d3/ffffffff at 12]
		// [match 20010da8/ffffffff at 24 match 80006023/ffffffff at 28 match 00000000/ffffffff at 32 match 00000230/ffffffff at 36]
		outputMatchLines := outputLines[slow+1 : fast]
		slow = fast

		restoreCIDR, err := restoreIPv6HexCIDR(outputMatchLines)
		if err != nil {
			return classAndHandleList, false, err
		}

		if restoreCIDR == hexCIDR {
			resultTmp := []string{matches[2], matches[1]}
			classAndHandleList = append(classAndHandleList, resultTmp)
		}
	}
	if len(classAndHandleList) > 0 {
		return classAndHandleList, true, nil
	}
	return classAndHandleList, false, nil
}

// isFilterMatchLine checks whether a line is in the format of `match <cidr> at <number>`
func isFilterMatchLine(line string) bool {
	return strings.Contains(line, "match")
}

// restoreIPv6HexCIDR restores IPv6 CIDR from match lines of tc filter output
func restoreIPv6HexCIDR(outputMatchLines []string) (string, error) {
	if len(outputMatchLines) == 0 {
		return hexCIDRZeroIPv6, nil
	}

	var ipv6Address, ipv6Mask string
	for _, line := range outputMatchLines {
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

	rowShort := maxRowOfMatchLinePerIPv6CIDR - len(outputMatchLines)
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

	for i := 0; i < len(outputLines); i++ {
		matches := classAndHandleIPv4Matcher.FindStringSubmatch(outputLines[i])
		if len(matches) != 3 {
			continue
		}

		if i+1 >= len(outputLines) {
			return nil, fmt.Errorf("unexpected output after: %v", outputLines[i])
		}

		parts := strings.Split(outputLines[i+1], " ")
		// expected tc line:
		// match <cidr> at <number>
		if len(parts) != 4 {
			return nil, fmt.Errorf("unexpected output: %v", parts)
		}
		cidr, err := asciiCIDR(parts[1])
		if err != nil {
			return nil, err
		}
		i++
		result = append(result, cidr)
	}

	return result, nil
}

func (t *tcShaper) getIPv6CIDRs(outputLines []string) ([]string, error) {
	result := []string{}

	// Since the match line num of `tc filter show dev xxx` output varies from 0 to 4 for IPv6 cidr,
	// slow and fast are two indexes that indicate the range of match lines in the output.
	// When slow finds a flowid line, fast continues to search for the succeeding flowid line or end of output from the position of slow.
	var slow, fast int = 0, 0
	for slow < len(outputLines) {
		matches := classAndHandleIPv6Matcher.FindStringSubmatch(outputLines[slow])
		if len(matches) != 3 {
			slow++
			continue
		}
		// expected outputLines[slow]:
		// filter parent 1: protocol ipv6 pref 2 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
		fast = slow + 1
		for fast < len(outputLines) {
			if !isFilterMatchLine(outputLines[fast]) {
				break
			}
			fast++
		}
		// e.g. outputMatchLines:
		// [match 20010db8/ffffffff at 8 match 86a308d3/ffffffff at 12]
		// [match 20010da8/ffffffff at 24 match 80006023/ffffffff at 28 match 00000000/ffffffff at 32 match 00000230/ffffffff at 36]
		outputMatchLines := outputLines[slow+1 : fast]
		slow = fast

		restoreCIDR, err := restoreIPv6HexCIDR(outputMatchLines)
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
	exitErr, ok := err.(*exec.ExitErrorWrapper)
	if ok {
		return exitErr.ExitCode() == 0x2
	}
	return false
}
