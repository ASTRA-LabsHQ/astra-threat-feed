package feeds

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0x-singularity/astra-threat-feed/internal/ioc"
)

const emergingURL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

type EmergingThreats struct {
	client *http.Client
}

func NewEmergingThreats() *EmergingThreats {
	return &EmergingThreats{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *EmergingThreats) Name() string { return "emerging_threats" }

func (f *EmergingThreats) Fetch() ([]ioc.IOC, error) {
	resp, err := f.client.Get(emergingURL)
	if err != nil {
		return nil, fmt.Errorf("fetching emerging threats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emerging threats returned status %d", resp.StatusCode)
	}

	var items []ioc.IOC
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip CIDR ranges — only process individual IPs.
		if strings.Contains(line, "/") {
			continue
		}
		if net.ParseIP(line) == nil {
			continue
		}
		items = append(items, ioc.IOC{
			Value:   line,
			Type:    ioc.TypeIPDst,
			Source:  f.Name(),
			Comment: "Compromised host - Emerging Threats",
			Tags:    []string{"type:compromised", "tlp:clear"},
			Seen:    time.Now().UTC(),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading emerging threats response: %w", err)
	}
	return items, nil
}
