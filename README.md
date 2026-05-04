# astra-threat-feed

An open-source threat intelligence feed aggregator built in Go. It collects indicators of
compromise (IOCs) from multiple free, publicly available sources, normalizes and deduplicates
them in a local SQLite database, and publishes a standards-compliant
[MISP](https://www.misp-project.org/) feed as static JSON files. The feed is automatically
refreshed every six hours via GitHub Actions and served through GitHub Pages.

The feed URL is: `https://astra-labshq.github.io/astra-threat-feed/`

## Feed Sources

| Source | IOC Types | Category |
|--------|-----------|----------|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | IP | Botnet command and control servers |
| [URLhaus](https://urlhaus.abuse.ch/) | Domain | Active malware distribution sites |
| [ThreatFox](https://threatfox.abuse.ch/) | IP, Domain, MD5, SHA256 | Mixed malware IOCs |
| [MalwareBazaar](https://bazaar.abuse.ch/) | MD5, SHA1, SHA256 | Malware file hashes |
| [Emerging Threats](https://rules.emergingthreats.net/) | IP | Compromised hosts |

All sources are free to use and require no API keys.

## IOC Coverage

- **IP addresses** (`ip-dst`): Botnet C2 servers and compromised hosts
- **Domains** (`domain`): Malware distribution infrastructure
- **File hashes** (`md5`, `sha1`, `sha256`): Malware samples from MalwareBazaar and ThreatFox

All attributes are tagged with [TLP:CLEAR](https://www.first.org/tlp/) and marked
`to_ids: true`, indicating they are suitable for use in detection tooling.

## Requirements

- Go 1.22 or later

## Getting Started

```bash
# Clone the repository
git clone https://github.com/ASTRA-LabsHQ/astra-threat-feed
cd astra-threat-feed

# Install dependencies
make tidy

# Copy and edit the config
cp config.example.yaml config.yaml

# Fetch IOCs from all sources and generate the MISP feed
make sync
```

The generated feed files are written to `./output/` by default.

## Commands

```
astra-feed sync      Fetch from all feeds then write MISP files
astra-feed fetch     Fetch IOCs and store in the database only
astra-feed generate  Generate MISP files from the existing database
astra-feed stats     Print IOC counts by type and source
```

Pass `-config <path>` to use a config file other than `./config.yaml`.

## Configuration

```yaml
database:
  path: "./astra-feed.db"  # SQLite database path

output:
  path: "./output"          # Directory for generated MISP files

misp:
  org_name: "Astra Labs"
  org_uuid: ""              # Leave empty to auto-derive from org name

feeds:
  feodo_tracker:
    enabled: true
  urlhaus:
    enabled: true
  threatfox:
    enabled: true
    days: 7                 # How many days back to query
  malware_bazaar:
    enabled: true
    limit: 100              # Number of recent samples to fetch
  emerging_threats:
    enabled: true
```

## MISP Feed Structure

After running `sync` or `generate`, the `output/` directory contains:

```
output/
├── manifest.json       # Event index consumed by MISP
├── <uuid>.json         # One event file per feed source
└── ...
```

Each source maps to a single MISP event with a deterministic UUID derived from the source
name, so the UUID is stable across runs without persisting any state. Attributes carry
threat level, TLP tag, and category metadata in the MISP format.

## Automated Publishing via GitHub Actions

The workflow at [`.github/workflows/sync.yml`](.github/workflows/sync.yml) runs every six
hours on a cron schedule (and can be triggered manually from the Actions tab). It:

1. Builds the `astra-feed` binary from source
2. Runs `astra-feed sync` to pull fresh IOCs and generate MISP JSON files
3. Pushes the contents of `output/` to the `gh-pages` branch using
   [peaceiris/actions-gh-pages](https://github.com/peaceiris/actions-gh-pages)

GitHub Pages then serves the `gh-pages` branch at the feed URL above.

### Enabling GitHub Pages

1. Go to the repository **Settings > Pages**
2. Set the source to **Deploy from a branch**
3. Select the `gh-pages` branch and the `/ (root)` folder
4. Save — the feed URL will be active after the first workflow run

### Adding the Feed to a MISP Instance

In your MISP instance, navigate to **Sync Actions > List Feeds > Add Feed** and configure:

| Field | Value |
|-------|-------|
| Name | Astra Labs Threat Feed |
| Provider | Astra Labs |
| Input Source | Network |
| URL | `https://astra-labshq.github.io/astra-threat-feed/` |
| Feed format | MISP Feed |

## Repository Layout

```
astra-threat-feed/
├── .github/workflows/sync.yml   Scheduled sync and GitHub Pages deployment
├── cmd/astra-feed/              CLI entrypoint
├── internal/
│   ├── config/                  YAML config loading
│   ├── database/                SQLite storage and IOC deduplication
│   ├── feeds/                   One file per feed source
│   ├── ioc/                     IOC type definitions and MISP category mapping
│   └── misp/                    MISP event and manifest generation
├── config.example.yaml          Annotated example configuration
└── Makefile                     Common tasks: build, sync, fetch, generate, stats
```

The `.claude/` directory contains AI-assisted development tooling and is excluded from the
repository via `.gitignore`.

## Contributing

Contributions are welcome. To add a new feed source:

1. Create `internal/feeds/<name>.go` implementing the `feeds.Feed` interface
   (two methods: `Name() string` and `Fetch() ([]ioc.IOC, error)`).
2. Register it in `internal/feeds/feed.go` inside `All()`.
3. Add the corresponding config fields to `internal/config/config.go` and `config.example.yaml`.
4. Add feed metadata (event description, MISP threat level, tags) to `feedMetadata` in
   `internal/misp/generator.go`.
5. Open a pull request with a brief description of the source and any licensing notes.

Please ensure any new source is freely accessible without account registration.

## Automating Updates Locally

To run the sync on your own schedule instead of using GitHub Actions:

```cron
0 */6 * * * cd /path/to/astra-threat-feed && ./astra-feed sync >> /var/log/astra-feed.log 2>&1
```

## License

MIT
