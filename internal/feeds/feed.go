package feeds

import (
	"github.com/0x-singularity/astra-threat-feed/internal/config"
	"github.com/0x-singularity/astra-threat-feed/internal/ioc"
)

// Feed is the interface all feed sources implement.
type Feed interface {
	Name() string
	Fetch() ([]ioc.IOC, error)
}

// All returns the enabled feeds based on cfg.
func All(cfg *config.Config) []Feed {
	var active []Feed
	if cfg.Feeds.FeodoTracker.Enabled {
		active = append(active, NewFeodoTracker())
	}
	if cfg.Feeds.URLhaus.Enabled {
		active = append(active, NewURLhaus())
	}
	if cfg.Feeds.ThreatFox.Enabled {
		active = append(active, NewThreatFox(cfg.Feeds.ThreatFox.Days))
	}
	if cfg.Feeds.MalwareBazaar.Enabled {
		active = append(active, NewMalwareBazaar(cfg.Feeds.MalwareBazaar.Limit))
	}
	if cfg.Feeds.EmergingThreats.Enabled {
		active = append(active, NewEmergingThreats())
	}
	return active
}
