package misp

type Event struct {
	Event EventData `json:"Event"`
}

type EventData struct {
	UUID          string      `json:"uuid"`
	Info          string      `json:"info"`
	Date          string      `json:"date"`
	ThreatLevelID string      `json:"threat_level_id"`
	Analysis      string      `json:"analysis"`
	Distribution  string      `json:"distribution"`
	Published     bool        `json:"published"`
	Timestamp     string      `json:"timestamp"`
	Org           Org         `json:"Org"`
	Orgc          Org         `json:"Orgc"`
	Tag           []Tag       `json:"Tag"`
	Attribute     []Attribute `json:"Attribute"`
}

type Org struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Local bool   `json:"local"`
}

type Tag struct {
	Name   string `json:"name"`
	Colour string `json:"colour"`
}

type Attribute struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	Comment   string `json:"comment"`
	ToIDS     bool   `json:"to_ids"`
	Timestamp string `json:"timestamp"`
}

// ManifestEntry is the per-event entry written into manifest.json.
type ManifestEntry struct {
	Orgc          Org    `json:"Orgc"`
	Tag           []Tag  `json:"Tag"`
	Info          string `json:"info"`
	Date          string `json:"date"`
	Analysis      string `json:"analysis"`
	ThreatLevelID string `json:"threat_level_id"`
	Timestamp     string `json:"timestamp"`
	UUID          string `json:"uuid"`
}
