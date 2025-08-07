package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	targetFile = "C:\\Users\\Public\\target.txt" // File you want to monitor and delete
)

func main() {
	watchDir := filepath.Dir(targetFile)
	watchHandle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(watchDir),
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		fmt.Printf("[-] Failed to open directory handle: %v\n", err)
		return
	}
	defer windows.CloseHandle(watchHandle)

	fmt.Printf("[*] Monitoring folder: %s\n", watchDir)

	buf := make([]byte, 4096)
	for {
		var bytesReturned uint32
		err = windows.ReadDirectoryChanges(
			watchHandle,
			&buf[0],
			uint32(len(buf)),
			false, // non-recursive
			windows.FILE_NOTIFY_CHANGE_FILE_NAME|
				windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
			&bytesReturned,
			nil,
			nil,
		)
		if err != nil {
			fmt.Printf("[-] Failed to read directory changes: %v\n", err)
			continue
		}

		offset := 0
		for {
			info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buf[offset]))
			filename := windows.UTF16ToString(info.FileName[:info.FileNameLength/2])
			fullPath := filepath.Join(watchDir, filename)

			if filepath.Clean(fullPath) == filepath.Clean(targetFile) {
				fmt.Printf("[+] Detected write to %s. Attempting to delete...\n", fullPath)
				deleteFile(fullPath)
			}

			if info.NextEntryOffset == 0 {
				break
			}
			offset += int(info.NextEntryOffset)
		}
	}
}

func deleteFile(path string) {
	// Wait a moment in case the writer has a lock
	time.Sleep(100 * time.Millisecond)

	err := os.Remove(path)
	if err != nil {
		fmt.Printf("[-] Failed to delete file: %v\n", err)
	} else {
		fmt.Printf("[+] File deleted: %s\n", path)
	}
}
