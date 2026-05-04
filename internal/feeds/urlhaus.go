package feeds

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0x-singularity/astra-threat-feed/internal/ioc"
)

const urlhausURL = "https://urlhaus.abuse.ch/downloads/text_recent/"

type URLhaus struct {
	client *http.Client
}

func NewURLhaus() *URLhaus {
	return &URLhaus{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *URLhaus) Name() string { return "urlhaus" }

func (f *URLhaus) Fetch() ([]ioc.IOC, error) {
	resp, err := f.client.Get(urlhausURL)
	if err != nil {
		return nil, fmt.Errorf("fetching urlhaus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlhaus returned status %d", resp.StatusCode)
	}

	seen := make(map[string]bool)
	var items []ioc.IOC

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		items = append(items, ioc.IOC{
			Value:   host,
			Type:    ioc.TypeDomain,
			Source:  f.Name(),
			Comment: "Malware distribution - URLhaus",
			Tags:    []string{"type:malware-distribution", "tlp:clear"},
			Seen:    time.Now().UTC(),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading urlhaus response: %w", err)
	}
	return items, nil
}
