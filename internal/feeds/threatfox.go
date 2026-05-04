package feeds

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/ioc"
)

const threatfoxURL = "https://threatfox-api.abuse.ch/api/v1/"

type ThreatFox struct {
	client *http.Client
	days   int
}

func NewThreatFox(days int) *ThreatFox {
	if days <= 0 {
		days = 7
	}
	return &ThreatFox{
		client: &http.Client{Timeout: 60 * time.Second},
		days:   days,
	}
}

func (f *ThreatFox) Name() string { return "threatfox" }

type threatfoxRequest struct {
	Query string `json:"query"`
	Days  int    `json:"days"`
}

type threatfoxResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		IOCType  string `json:"ioc_type"`
		IOCValue string `json:"ioc_value"`
		MalwareAlias string `json:"malware_alias"`
		Confidence   int    `json:"confidence"`
	} `json:"data"`
}

func (f *ThreatFox) Fetch() ([]ioc.IOC, error) {
	body, _ := json.Marshal(threatfoxRequest{Query: "get_iocs", Days: f.days})
	resp, err := f.client.Post(threatfoxURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("fetching threatfox: %w", err)
	}
	defer resp.Body.Close()

	var result threatfoxResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding threatfox response: %w", err)
	}
	if result.QueryStatus != "ok" {
		return nil, fmt.Errorf("threatfox returned status %q", result.QueryStatus)
	}

	var items []ioc.IOC
	for _, entry := range result.Data {
		item, ok := parseThreatFoxEntry(entry.IOCType, entry.IOCValue, entry.MalwareAlias)
		if !ok {
			continue
		}
		item.Source = f.Name()
		items = append(items, item)
	}
	return items, nil
}

func parseThreatFoxEntry(iocType, value, malware string) (ioc.IOC, bool) {
	comment := "ThreatFox"
	if malware != "" {
		comment = fmt.Sprintf("ThreatFox - %s", malware)
	}
	tags := []string{"tlp:clear"}

	switch iocType {
	case "ip:port":
		// value is "1.2.3.4:443" — strip the port
		host, _, err := net.SplitHostPort(value)
		if err != nil {
			// try treating the whole value as an IP
			host = value
		}
		if net.ParseIP(host) == nil {
			return ioc.IOC{}, false
		}
		return ioc.IOC{
			Value:   host,
			Type:    ioc.TypeIPDst,
			Comment: comment,
			Tags:    append(tags, "type:c2"),
			Seen:    time.Now().UTC(),
		}, true

	case "domain":
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return ioc.IOC{}, false
		}
		return ioc.IOC{
			Value:   value,
			Type:    ioc.TypeDomain,
			Comment: comment,
			Tags:    append(tags, "type:malware"),
			Seen:    time.Now().UTC(),
		}, true

	case "md5_hash":
		value = strings.ToLower(strings.TrimSpace(value))
		if len(value) != 32 {
			return ioc.IOC{}, false
		}
		return ioc.IOC{
			Value:   value,
			Type:    ioc.TypeMD5,
			Comment: comment,
			Tags:    append(tags, "type:malware"),
			Seen:    time.Now().UTC(),
		}, true

	case "sha256_hash":
		value = strings.ToLower(strings.TrimSpace(value))
		if len(value) != 64 {
			return ioc.IOC{}, false
		}
		return ioc.IOC{
			Value:   value,
			Type:    ioc.TypeSHA256,
			Comment: comment,
			Tags:    append(tags, "type:malware"),
			Seen:    time.Now().UTC(),
		}, true
	}
	return ioc.IOC{}, false
}
