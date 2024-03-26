// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scrape

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

type TrieEntry struct {
	Entries  map[string]*TrieEntry
	Terminal bool
}

var usedMetricsTrie = &TrieEntry{
	Entries: make(map[string]*TrieEntry),
}

func (e *TrieEntry) Add(components []string) {
	if len(components) == 0 {
		e.Terminal = true
		return
	}

	entry, found := e.Entries[components[0]]
	if !found {
		entry = &TrieEntry{
			Entries:  make(map[string]*TrieEntry),
			Terminal: false,
		}
		e.Entries[components[0]] = entry
	}

	entry.Add(components[1:])
}

func (e *TrieEntry) Query(components [][]byte) bool {
	if len(components) == 0 {
		return e.Terminal
	}

	entry, found := e.Entries[string(components[0])]
	if !found {
		return false
	}

	if entry.Terminal {
		return true
	}

	return entry.Query(components[1:])
}

func init() {
	usedMetricsJSON := os.Getenv("CC_PATCH_USED_METRICS")
	if usedMetricsJSON != "" {
		f, err := os.Open(usedMetricsJSON)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		var metricsList []string
		err = json.NewDecoder(f).Decode(&metricsList)
		if err != nil {
			panic(err)
		}

		for _, m := range metricsList {
			usedMetricsTrie.Add(strings.Split(m, "_"))
		}
	}
}

func hideUnusedMetrics(response []byte) []byte {
	if len(usedMetricsTrie.Entries) == 0 {
		return response
	}

	var outputBuf bytes.Buffer

	lines := bytes.Split(response, []byte("\n"))
	for _, line := range lines {
		trimmedLine := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmedLine, []byte("#")) {
			lineParts := bytes.SplitN(bytes.TrimSpace(bytes.TrimPrefix(trimmedLine, []byte("#"))), []byte(" "), 3)

			// write into buffer if it looks like # TYPE metric_name metadata
			if bytes.Equal(lineParts[0], []byte("EOF")) || (len(lineParts) > 1 &&
				usedMetricsTrie.Query(bytes.Split(lineParts[1], []byte("_")))) {
				outputBuf.Write(line)
				outputBuf.WriteByte('\n')
				continue
			}
		}

		metricComponent := bytes.SplitN(trimmedLine, []byte("{"), 2)[0]
		if usedMetricsTrie.Query(bytes.Split(metricComponent, []byte("_"))) {
			outputBuf.Write(line)
			outputBuf.WriteByte('\n')
			continue
		}
	}

	return outputBuf.Bytes()
}
