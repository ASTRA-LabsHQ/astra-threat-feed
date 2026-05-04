package misp

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/config"
	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/database"
	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/ioc"
	"github.com/google/uuid"
)

// astraNamespace is the fixed UUID v5 namespace for all Astra Labs MISP identifiers.
// Changing this value would alter all event and org UUIDs, breaking existing MISP subscriptions.
var astraNamespace = uuid.MustParse("4a73b2c1-9e4f-4d8a-b3e7-2f1c8d5a9b0e")

type feedMeta struct {
	info        string
	threatLevel string
	tags        []Tag
}

var feedMetadata = map[string]feedMeta{
	"feodo_tracker": {
		info:        "Botnet Command and Control IPs - Feodo Tracker",
		threatLevel: "1",
		tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}, {Name: "type:botnet-c2", Colour: "#ff6600"}},
	},
	"urlhaus": {
		info:        "Malware Distribution Domains - URLhaus",
		threatLevel: "1",
		tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}, {Name: "type:malware-distribution", Colour: "#cc0000"}},
	},
	"threatfox": {
		info:        "Multi-type IOC Feed - ThreatFox",
		threatLevel: "2",
		tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}, {Name: "type:malware", Colour: "#cc0000"}},
	},
	"malware_bazaar": {
		info:        "Malware File Hashes - MalwareBazaar",
		threatLevel: "1",
		tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}, {Name: "type:malware", Colour: "#cc0000"}},
	},
	"emerging_threats": {
		info:        "Compromised Host IPs - Emerging Threats",
		threatLevel: "2",
		tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}, {Name: "type:compromised", Colour: "#ff9900"}},
	},
}

// feedDisplay holds the data passed to the index.html template.
type feedDisplay struct {
	Name      string
	IOCTypes  string
	Category  string
	URL       string
	Count     int
}

type indexData struct {
	UpdatedAt string
	FeedURL   string
	RepoURL   string
	OrgName   string
	Feeds     []feedDisplay
	Total     int
}

var feedDisplay_ = map[string]feedDisplay{
	"feodo_tracker":   {Name: "Feodo Tracker", IOCTypes: "IP", Category: "Botnet C2 servers", URL: "https://feodotracker.abuse.ch/"},
	"urlhaus":         {Name: "URLhaus", IOCTypes: "Domain", Category: "Malware distribution sites", URL: "https://urlhaus.abuse.ch/"},
	"threatfox":       {Name: "ThreatFox", IOCTypes: "IP, Domain, MD5, SHA256", Category: "Mixed malware IOCs", URL: "https://threatfox.abuse.ch/"},
	"malware_bazaar":  {Name: "MalwareBazaar", IOCTypes: "MD5, SHA1, SHA256", Category: "Malware file hashes", URL: "https://bazaar.abuse.ch/"},
	"emerging_threats":{Name: "Emerging Threats", IOCTypes: "IP", Category: "Compromised hosts", URL: "https://rules.emergingthreats.net/"},
}

var indexTmplSrc = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Astra Labs Threat Feed</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      background: #0d1117;
      color: #c9d1d9;
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container { max-width: 860px; margin: 0 auto; }
    header { border-bottom: 1px solid #21262d; padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { font-size: 1.75rem; color: #f0f6fc; font-weight: 600; }
    h1 span { color: #58a6ff; }
    .subtitle { color: #8b949e; margin-top: 0.4rem; font-size: 0.95rem; }
    h2 { font-size: 1rem; color: #f0f6fc; font-weight: 600; margin-bottom: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.8rem; }
    .section { margin-bottom: 2rem; }
    .card {
      background: #161b22;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 1.25rem 1.5rem;
    }
    .feed-url {
      font-family: monospace;
      font-size: 0.9rem;
      color: #58a6ff;
      word-break: break-all;
    }
    .misp-block {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 4px;
      padding: 0.75rem 1rem;
      margin-top: 0.75rem;
      font-size: 0.85rem;
    }
    .misp-block table { width: 100%; border-collapse: collapse; }
    .misp-block td { padding: 0.2rem 0.5rem; vertical-align: top; }
    .misp-block td:first-child { color: #8b949e; white-space: nowrap; padding-right: 1rem; }
    .misp-block td:last-child { font-family: monospace; color: #e6edf3; }
    table.sources { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    table.sources th {
      text-align: left;
      color: #8b949e;
      font-weight: 500;
      padding: 0.4rem 0.75rem;
      border-bottom: 1px solid #21262d;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    table.sources td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #161b22; vertical-align: middle; }
    table.sources tr:last-child td { border-bottom: none; }
    table.sources a { color: #58a6ff; text-decoration: none; }
    table.sources a:hover { text-decoration: underline; }
    .badge {
      display: inline-block;
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 12px;
      background: #1f2937;
      border: 1px solid #374151;
      color: #9ca3af;
      margin-right: 0.25rem;
      font-family: monospace;
    }
    .count { color: #8b949e; font-size: 0.8rem; text-align: right; }
    .meta { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
    .updated { color: #8b949e; font-size: 0.8rem; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #21262d; font-size: 0.8rem; color: #8b949e; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
    footer a { color: #58a6ff; text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    .tlp {
      display: inline-block;
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
      background: #ffffff20;
      color: #f0f6fc;
      font-weight: 600;
      letter-spacing: 0.03em;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1><span>Astra Labs</span> Threat Feed</h1>
      <p class="subtitle">
        A MISP-compatible open-source threat intelligence feed aggregating IOCs from
        multiple free public sources. Updated every six hours.
        <span class="tlp">TLP:CLEAR</span>
      </p>
    </header>

    <div class="section">
      <h2>Feed Endpoint</h2>
      <div class="card">
        <p class="feed-url">{{.FeedURL}}</p>
        <div class="misp-block">
          <table>
            <tr><td>Name</td><td>{{.OrgName}} Threat Feed</td></tr>
            <tr><td>Provider</td><td>{{.OrgName}}</td></tr>
            <tr><td>Input Source</td><td>Network</td></tr>
            <tr><td>URL</td><td>{{.FeedURL}}</td></tr>
            <tr><td>Feed format</td><td>MISP Feed</td></tr>
          </table>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="meta">
        <h2>Active Sources</h2>
        <span class="updated">{{.Total}} total indicators &mdash; last updated {{.UpdatedAt}}</span>
      </div>
      <div class="card" style="padding: 0;">
        <table class="sources">
          <thead>
            <tr>
              <th>Source</th>
              <th>IOC Types</th>
              <th>Category</th>
              <th style="text-align:right;">Count</th>
            </tr>
          </thead>
          <tbody>
            {{range .Feeds}}
            <tr>
              <td><a href="{{.URL}}" target="_blank" rel="noopener">{{.Name}}</a></td>
              <td>{{range $i, $t := splitTypes .IOCTypes}}<span class="badge">{{$t}}</span>{{end}}</td>
              <td style="color:#8b949e;">{{.Category}}</td>
              <td class="count">{{if gt .Count 0}}{{.Count}}{{else}}&mdash;{{end}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </div>

    <footer>
      <span>Open source &mdash; <a href="{{.RepoURL}}" target="_blank" rel="noopener">View on GitHub</a></span>
      <span>All data is <span class="tlp">TLP:CLEAR</span> and freely redistributable</span>
    </footer>
  </div>
</body>
</html>
`

type Generator struct {
	cfg *config.Config
	db  *database.DB
}

func NewGenerator(cfg *config.Config, db *database.DB) *Generator {
	return &Generator{cfg: cfg, db: db}
}

func (g *Generator) Generate() error {
	if err := os.MkdirAll(g.cfg.Output.Path, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	orgUUID := g.cfg.MISP.OrgUUID
	if orgUUID == "" {
		// Deterministic org UUID derived from the org name so it never changes.
		orgUUID = uuid.NewSHA1(astraNamespace, []byte(g.cfg.MISP.OrgName)).String()
	}
	org := Org{Name: g.cfg.MISP.OrgName, UUID: orgUUID}

	sources, err := g.db.GetDistinctSources()
	if err != nil {
		return fmt.Errorf("getting sources: %w", err)
	}

	manifest := make(map[string]ManifestEntry)
	now := time.Now().UTC()
	sourceCounts := make(map[string]int)

	for _, source := range sources {
		items, err := g.db.GetIOCsBySource(source)
		if err != nil {
			return fmt.Errorf("loading IOCs for %s: %w", source, err)
		}
		if len(items) == 0 {
			continue
		}

		// Deterministic UUID per feed source — stable across runs without persisting state.
		eventUUID := uuid.NewSHA1(astraNamespace, []byte(source)).String()

		meta, ok := feedMetadata[source]
		if !ok {
			meta = feedMeta{
				info:        fmt.Sprintf("Astra Threat Feed - %s", source),
				threatLevel: "3",
				tags:        []Tag{{Name: "tlp:clear", Colour: "#ffffff"}},
			}
		}

		ts := strconv.FormatInt(now.Unix(), 10)
		attrs := buildAttributes(items, ts)
		sourceCounts[source] = len(attrs)

		event := Event{
			Event: EventData{
				UUID:          eventUUID,
				Info:          meta.info,
				Date:          now.Format("2006-01-02"),
				ThreatLevelID: meta.threatLevel,
				Analysis:      "2",
				Distribution:  "3",
				Published:     true,
				Timestamp:     ts,
				Org:           org,
				Orgc:          org,
				Tag:           meta.tags,
				Attribute:     attrs,
			},
		}

		if err := writeJSON(filepath.Join(g.cfg.Output.Path, eventUUID+".json"), event); err != nil {
			return fmt.Errorf("writing event file for %s: %w", source, err)
		}

		manifest[eventUUID] = ManifestEntry{
			Orgc:          org,
			Tag:           meta.tags,
			Info:          meta.info,
			Date:          now.Format("2006-01-02"),
			Analysis:      "2",
			ThreatLevelID: meta.threatLevel,
			Timestamp:     ts,
			UUID:          eventUUID,
		}

		fmt.Printf("  wrote %s (%d attributes)\n", source, len(attrs))
	}

	if err := writeJSON(filepath.Join(g.cfg.Output.Path, "manifest.json"), manifest); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	fmt.Printf("  wrote manifest.json (%d events)\n", len(manifest))

	if err := g.writeIndex(sourceCounts, now); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}
	return nil
}

func (g *Generator) writeIndex(counts map[string]int, now time.Time) error {
	order := []string{"feodo_tracker", "urlhaus", "threatfox", "malware_bazaar", "emerging_threats"}

	var feeds []feedDisplay
	total := 0
	for _, key := range order {
		d, ok := feedDisplay_[key]
		if !ok {
			continue
		}
		d.Count = counts[key]
		total += d.Count
		feeds = append(feeds, d)
	}

	data := indexData{
		UpdatedAt: now.Format("2 Jan 2006 15:04 UTC"),
		FeedURL:   "https://feed.astra-labs.co/",
		RepoURL:   "https://github.com/ASTRA-LabsHQ/astra-threat-feed",
		OrgName:   g.cfg.MISP.OrgName,
		Feeds:     feeds,
		Total:     total,
	}

	tmpl := template.Must(template.New("index").Funcs(template.FuncMap{
		"splitTypes": func(s string) []string {
			var out []string
			start := 0
			for i := 0; i <= len(s); i++ {
				if i == len(s) || s[i] == ',' {
					part := s[start:i]
					for len(part) > 0 && part[0] == ' ' {
						part = part[1:]
					}
					if part != "" {
						out = append(out, part)
					}
					start = i + 1
				}
			}
			return out
		},
	}).Parse(indexTmplSrc))

	f, err := os.Create(filepath.Join(g.cfg.Output.Path, "index.html"))
	if err != nil {
		return err
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("executing index template: %w", err)
	}
	fmt.Println("  wrote index.html")
	return nil
}

func buildAttributes(items []ioc.IOC, ts string) []Attribute {
	attrs := make([]Attribute, 0, len(items))
	for _, item := range items {
		attrs = append(attrs, Attribute{
			UUID:      uuid.New().String(),
			Type:      item.Type,
			Category:  ioc.Category(item.Type),
			Value:     item.Value,
			Comment:   item.Comment,
			ToIDS:     true,
			Timestamp: ts,
		})
	}
	return attrs
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
