package misp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/0x-singularity/astra-threat-feed/internal/config"
	"github.com/0x-singularity/astra-threat-feed/internal/database"
	"github.com/0x-singularity/astra-threat-feed/internal/ioc"
	"github.com/google/uuid"
)

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
		orgUUID = uuid.New().String()
	}
	org := Org{Name: g.cfg.MISP.OrgName, UUID: orgUUID}

	sources, err := g.db.GetDistinctSources()
	if err != nil {
		return fmt.Errorf("getting sources: %w", err)
	}

	manifest := make(map[string]ManifestEntry)
	now := time.Now().UTC()

	for _, source := range sources {
		items, err := g.db.GetIOCsBySource(source)
		if err != nil {
			return fmt.Errorf("loading IOCs for %s: %w", source, err)
		}
		if len(items) == 0 {
			continue
		}

		eventUUID, err := g.db.GetOrCreateEventUUID(source)
		if err != nil {
			return fmt.Errorf("getting event UUID for %s: %w", source, err)
		}

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
