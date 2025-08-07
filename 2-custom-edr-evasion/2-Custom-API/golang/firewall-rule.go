package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	targetPorts := map[string]bool{
		"9200": true,
		"5400": true,
	}

	droppedIPs := make(map[string]bool)

	// Run netstat to get current TCP connections
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[-] Error running netstat:", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Regex to match lines like:
	// TCP    192.168.1.100:50497   192.168.1.200:9200   ESTABLISHED     1234
	re := regexp.MustCompile(`^\s*TCP\s+\S+:(\d+)\s+([\d\.]+):(\d+)\s+ESTABLISHED\s+\d+`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			remoteIP := matches[2]
			port := matches[3]

			if targetPorts[port] && !droppedIPs[remoteIP] {
				fmt.Printf("[+] Dropping outbound connection to %s (port %s)\n", remoteIP, port)
				droppedIPs[remoteIP] = true
				addDropRule(remoteIP)
			}
		}
	}
}

func addDropRule(ip string) {
	ruleName := fmt.Sprintf("DropWatch_%s", ip)

	// Silent DROP: no RST/ICMP, traffic is discarded quietly
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=out", "action=block",
		fmt.Sprintf("remoteip=%s", ip),
		"profile=any", "edge=no", "enable=yes")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[-] Failed to add drop rule for %s: %v\n", ip, err)
		fmt.Println(string(output))
	} else {
		fmt.Printf("[+] Silent drop rule added for %s\n", ip)
	}
}
