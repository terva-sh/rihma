//go:build dogfood

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"maunium.net/go/mautrix/id"
)

// logMark reads only output appended after the action's baseline. Keeping
// the original file identity also distinguishes rotation from the current log.
type logMark struct {
	path string
	info os.FileInfo
}

func markLog(path string) (logMark, error) {
	info, err := os.Stat(path)
	return logMark{path: path, info: info}, err
}

func (m logMark) read() ([]byte, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(m.info, info) || info.Size() < m.info.Size() {
		return nil, fmt.Errorf("log changed or was truncated during the check")
	}
	if _, err := f.Seek(m.info.Size(), io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// The CLI prefixes notices with the connector name. Some host surfaces
// present the line directly; accept both, but never a JSON diagnostic.
func operatorNotice(line string) string {
	if strings.HasPrefix(line, "connector \"") {
		_, rest, ok := strings.Cut(line, "\": ")
		if !ok {
			return ""
		}
		line = rest
	}
	if !strings.HasPrefix(line, "Matrix ") {
		return ""
	}
	return line
}

func oversizeEvidence(diagnostics, operator logMark, evt id.EventID) (dropped, warned bool, err error) {
	logs, err := diagnostics.read()
	if err != nil {
		return false, false, err
	}
	for _, line := range strings.Split(string(logs), "\n") {
		var entry struct {
			EventID string `json:"event_id"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.EventID == evt.String() && entry.Message == "dropping attachment" {
			dropped = true
		}
	}
	output, err := operator.read()
	if err != nil {
		return false, false, err
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = operatorNotice(line)
		if strings.HasPrefix(line, "Matrix room ") && strings.Contains(line, fmt.Sprintf("event %q: dropped attachment.", evt)) {
			warned = true
		}
	}
	return dropped, warned, nil
}
