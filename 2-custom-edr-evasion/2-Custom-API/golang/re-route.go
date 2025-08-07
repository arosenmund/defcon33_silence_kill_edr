package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Replace this with your actual gateway/interface if needed
const (
	defaultGateway = "127.0.0.1"
	metric         = "1"
)

func main() {
	targetPorts := map[string]bool{
		"9200": true,
		"5400": true,
	}

	establishedIPs := make(map[string]bool)

	// Run netstat -ano
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error running netstat:", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Sample line to match:
	//   TCP    192.168.1.100:50497   192.168.1.200:9200   ESTABLISHED     1234
	re := regexp.MustCompile(`^\s*TCP\s+\S+:(\d+)\s+([\d\.]+):(\d+)\s+ESTABLISHED\s+\d+`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			remoteIP := matches[2]
			port := matches[3]

			if targetPorts[port] {
				if !establishedIPs[remoteIP] {
					fmt.Printf("[+] Found ESTABLISHED connection to %s on port %s\n", remoteIP, port)
					establishedIPs[remoteIP] = true
				}
			}
		}
	}

	// Add route for each IP
	for ip := range establishedIPs {
		addRoute(ip)
	}
}

func addRoute(ip string) {
	cmd := exec.Command("route", "add", ip, "mask", "255.255.255.255", defaultGateway, "metric", metric)

	fmt.Printf("[*] Adding route for %s...\n", ip)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] Failed to add route for %s: %v\n", ip, err)
		fmt.Println(string(output))
		return
	}

	fmt.Printf("[+] Route added for %s\n", ip)
}

//notes: add a service that also listens via http on these same ports and responds with 200 OK no matter what is receeived.
