package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	Output struct {
		Path string `yaml:"path"`
	} `yaml:"output"`
	MISP struct {
		OrgName string `yaml:"org_name"`
		OrgUUID string `yaml:"org_uuid"`
	} `yaml:"misp"`
	Feeds struct {
		FeodoTracker struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"feodo_tracker"`
		URLhaus struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"urlhaus"`
		ThreatFox struct {
			Enabled bool `yaml:"enabled"`
			Days    int  `yaml:"days"`
		} `yaml:"threatfox"`
		MalwareBazaar struct {
			Enabled bool `yaml:"enabled"`
			Limit   int  `yaml:"limit"`
		} `yaml:"malware_bazaar"`
		EmergingThreats struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"emerging_threats"`
	} `yaml:"feeds"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Database.Path == "" {
		c.Database.Path = "./astra-feed.db"
	}
	if c.Output.Path == "" {
		c.Output.Path = "./output"
	}
	if c.MISP.OrgName == "" {
		c.MISP.OrgName = "Astra Labs"
	}
	if c.Feeds.ThreatFox.Days == 0 {
		c.Feeds.ThreatFox.Days = 7
	}
	if c.Feeds.MalwareBazaar.Limit == 0 {
		c.Feeds.MalwareBazaar.Limit = 100
	}
}
