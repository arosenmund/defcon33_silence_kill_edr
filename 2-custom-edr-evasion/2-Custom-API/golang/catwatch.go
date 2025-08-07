package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Asutorufa/windivert"
	"github.com/rivo/tview"
)

var (
	targetPorts = map[string]bool{
		"9200": true,
		"5400": true,
	}
	driverName = "WinDivert64.sys"
)

func main() {
	dashboard := flag.Bool("dashboard", false, "Enable dashboard UI")
	flag.Parse()

	if *dashboard {
		launchDashboard()
	} else {
		launchCLIMenu()
	}
}

func launchCLIMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\n=== Watch Suite Manager ===")
		fmt.Println("Select a module to run:")
		fmt.Println("1) Route Watch")
		fmt.Println("2) Drop Watch")
		fmt.Println("3) File Watch")
		fmt.Println("4) Service Kill")
		fmt.Println("5) Wire Watch")
		fmt.Println("0) Exit")
		fmt.Print("Enter your choice: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			runRouteWatch()
		case "2":
			runDropWatch()
		case "3":
			runFileWatch(reader)
		case "4":
			runServiceKill(reader)
		case "5":
			runWireWatch()
		case "0":
			fmt.Println("Exiting.")
			return
		default:
			fmt.Println("Invalid selection. Try again.")
		}
	}
}

func launchDashboard() {
	app := tview.NewApplication()
	menu := tview.NewList().
		AddItem("Route Watch", "Add route to IPs with 9200/5400 established", '1', func() {
			runRouteWatch()
		}).
		AddItem("Drop Watch", "Add silent drop firewall rules", '2', func() {
			runDropWatch()
		}).
		AddItem("File Watch", "Monitor and delete a file", '3', func() {
			runFileWatch(bufio.NewReader(os.Stdin))
		}).
		AddItem("Service Kill", "Stop and disable a Windows service", '4', func() {
			runServiceKill(bufio.NewReader(os.Stdin))
		}).
		AddItem("Wire Watch", "Silently drop packets to target IPs", '5', func() {
			runWireWatch()
		}).
		AddItem("Exit", "Quit the dashboard", '0', func() {
			app.Stop()
		})
	menu.SetBorder(true).SetTitle("Watch Suite Dashboard").SetTitleAlign(tview.AlignLeft)
	if err := app.SetRoot(menu, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

func runRouteWatch() {
	fmt.Println("[Route Watch] Running...")
	ips := findTargetIPs()
	for _, ip := range ips {
		cmd := exec.Command("route", "add", ip, "mask", "255.255.255.255", "192.168.1.1", "metric", "1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("[-] Failed to add route for %s: %v\n", ip, err)
			fmt.Println(string(output))
		} else {
			fmt.Printf("[+] Route added for %s\n", ip)
		}
	}
}

func runDropWatch() {
	fmt.Println("[Drop Watch] Running...")
	ips := findTargetIPs()
	for _, ip := range ips {
		ruleName := fmt.Sprintf("DropWatch_%s", ip)
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
}

func runFileWatch(reader *bufio.Reader) {
	fmt.Println("[File Watch] Monitoring file for changes.")
	fmt.Print("Enter full path to the file to watch/delete: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	dir := filepath.Dir(filePath)
	targetFile := filepath.Base(filePath)

	watchHandle, err := os.Open(dir)
	if err != nil {
		fmt.Printf("[-] Failed to open directory: %v\n", err)
		return
	}
	defer watchHandle.Close()

	fmt.Printf("[*] Watching %s for writes...\n", filePath)

	for {
		time.Sleep(1 * time.Second)
		if _, err := os.Stat(filePath); err == nil {
			fmt.Printf("[!] File touched. Deleting %s\n", filePath)
			err := os.Remove(filePath)
			if err != nil {
				fmt.Printf("[-] Failed to delete: %v\n", err)
			} else {
				fmt.Println("[+] File deleted successfully.")
			}
		}
	}
}

func runServiceKill(reader *bufio.Reader) {
	fmt.Print("Enter service name to stop and disable: ")
	serviceName, _ := reader.ReadString('\n')
	serviceName = strings.TrimSpace(serviceName)

	cmd := exec.Command("sc", "stop", serviceName)
	output, err := cmd.CombinedOutput()
	fmt.Printf("[*] sc stop output:\n%s\n", string(output))
	if err != nil {
		fmt.Printf("[-] Failed to stop service %s: %v\n", serviceName, err)
		return
	}

	cmd = exec.Command("sc", "config", serviceName, "start=", "disabled")
	output, err = cmd.CombinedOutput()
	fmt.Printf("[*] sc config output:\n%s\n", string(output))
	if err != nil {
		fmt.Printf("[-] Failed to disable service %s: %v\n", serviceName, err)
	}
}

func runWireWatch() {
	fmt.Println("[Wire Watch] Running...")
	ips := findTargetIPs()
	if len(ips) == 0 {
		fmt.Println("[-] No target IPs found.")
		return
	}

	filter := "outbound and ("
	for i, ip := range ips {
		if i > 0 {
			filter += " or "
		}
		filter += fmt.Sprintf("ip.DstAddr == %s", ip)
	}
	filter += ")"

	handle, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		fmt.Printf("[-] Failed to open WinDivert: %v\n", err)
		return
	}
	defer handle.Close()

	packet := make([]byte, 1500)
	addr := new(windivert.Address)

	fmt.Println("[*] Dropping outbound packets to target IPs... (Ctrl+C to exit)")
	for {
		_, err := handle.Recv(packet, addr)
		if err != nil {
			continue
		}
		fmt.Printf("[DROP] Packet to %s\n", addr.IPv4Destination())
		// Do not re-inject to drop
	}

	// Optional: Remove driver from disk
	exeDir, _ := os.Executable()
	drvPath := filepath.Join(filepath.Dir(exeDir), driverName)
	os.Remove(drvPath)
}

func findTargetIPs() []string {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("[-] Failed to run netstat: %v\n", err)
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	re := regexp.MustCompile(`^\\s*TCP\\s+\\S+:(\\d+)\\s+([\\d\\.]+):(\\d+)\\s+ESTABLISHED\\s+\\d+`)

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
