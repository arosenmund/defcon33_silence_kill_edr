package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	watchDir      string
	targetPattern string
	recursive     bool
	debugEvents   bool
)

func main() {
	flag.StringVar(&watchDir, "dir", `C:\Users\Public`, "Directory to monitor (non-recursive unless -recursive)")
	flag.StringVar(&targetPattern, "match", `*.txt`, "Glob for filenames to delete on change")
	flag.BoolVar(&recursive, "recursive", false, "Monitor subdirectories recursively")
	flag.BoolVar(&debugEvents, "debug", true, "Print all file change events")
	flag.Parse()

	// Normalize
	watchDir = filepath.Clean(watchDir)

	// Open directory for change notifications
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(watchDir),
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // synchronous (no OVERLAPPED)
		0,
	)
	if err != nil {
		fmt.Printf("[-] CreateFile(%s) failed: %v\n", watchDir, err)
		return
	}
	defer windows.CloseHandle(h)

	fmt.Printf("[*] Watching: %s\n", watchDir)
	fmt.Printf("[*] Match:    %q (case-insensitive)\n", targetPattern)
	fmt.Printf("[*] Recursive: %v  Debug: %v\n", recursive, debugEvents)

	buf := make([]byte, 64*1024)

	const notifyMask = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES |
		windows.FILE_NOTIFY_CHANGE_SIZE |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_CREATION

	for {
		var bytesReturned uint32
		if err := windows.ReadDirectoryChanges(
			h,
			&buf[0],
			uint32(len(buf)),
			recursive,
			notifyMask,
			&bytesReturned,
			nil, // synchronous
			0,   // completion routine (uintptr)
		); err != nil {
			fmt.Printf("[-] ReadDirectoryChanges failed: %v\n", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}

		offset := 0
		for {
			info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buf[offset]))
			nameLen := int(info.FileNameLength / 2)
			nameSlice := unsafe.Slice(&info.FileName, nameLen)
			filename := windows.UTF16ToString(nameSlice)

			fullPath := filepath.Join(watchDir, filename)
			nameLower := strings.ToLower(filepath.Base(filename))
			patternLower := strings.ToLower(targetPattern)
			matched, _ := filepath.Match(patternLower, nameLower)

			if debugEvents {
				fmt.Printf("[evt] action=%d  file=%s  matched=%v\n", info.Action, fullPath, matched)
			}

			// Many tools: create temp -> write -> rename old -> rename new.
			// We delete on any of these if the name matches the glob.
			if matched {
				switch info.Action {
				case windows.FILE_ACTION_ADDED,
					windows.FILE_ACTION_MODIFIED,
					windows.FILE_ACTION_RENAMED_NEW_NAME,
					windows.FILE_ACTION_RENAMED_OLD_NAME,
					windows.FILE_ACTION_REMOVED:
					// tiny delay in case writer holds a handle
					time.Sleep(100 * time.Millisecond)
					if err := os.Remove(fullPath); err != nil {
						// If it was REMOVED already, this may just fail with not found.
						if debugEvents {
							fmt.Printf("[-] Delete failed for %s: %v\n", fullPath, err)
						}
					} else {
						fmt.Printf("[+] Deleted %s (action=%d)\n", fullPath, info.Action)
					}
				}
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
