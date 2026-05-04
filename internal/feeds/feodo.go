package feeds

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/ioc"
)

const feodoURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

type FeodoTracker struct {
	client *http.Client
}

func NewFeodoTracker() *FeodoTracker {
	return &FeodoTracker{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *FeodoTracker) Name() string { return "feodo_tracker" }

func (f *FeodoTracker) Fetch() ([]ioc.IOC, error) {
	resp, err := f.client.Get(feodoURL)
	if err != nil {
		return nil, fmt.Errorf("fetching feodo tracker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feodo tracker returned status %d", resp.StatusCode)
	}

	// Strip comment lines before passing to CSV reader.
	var sb strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			sb.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading feodo tracker response: %w", err)
	}

	r := csv.NewReader(strings.NewReader(sb.String()))
	r.FieldsPerRecord = -1

	var items []ioc.IOC
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 6 {
			continue
		}
		// Fields: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
		ipStr := strings.TrimSpace(record[1])
		if net.ParseIP(ipStr) == nil {
			continue
		}
		malware := strings.TrimSpace(record[5])
		comment := fmt.Sprintf("Botnet C2 - %s", malware)
		items = append(items, ioc.IOC{
			Value:   ipStr,
			Type:    ioc.TypeIPDst,
			Source:  f.Name(),
			Comment: comment,
			Tags:    []string{"type:botnet-c2", "tlp:clear"},
			Seen:    time.Now().UTC(),
		})
	}
	return items, nil
}
