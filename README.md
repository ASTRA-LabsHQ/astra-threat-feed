# astra-threat-feed

A MISP-compatible threat intelligence feed aggregator built in Go. It pulls IOCs from
free public sources, deduplicates them in a local SQLite database, and generates a
static MISP feed (manifest + event JSON files) ready to serve over HTTP or GitHub Pages.

## Feed Sources

| Feed | IOC Types | Notes |
|------|-----------|-------|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | IP | Botnet C2 servers |
| [URLhaus](https://urlhaus.abuse.ch/) | Domain | Malware distribution sites |
| [ThreatFox](https://threatfox.abuse.ch/) | IP, Domain, MD5, SHA256 | Mixed malware IOCs |
| [MalwareBazaar](https://bazaar.abuse.ch/) | MD5, SHA1, SHA256 | Malware file hashes |
| [Emerging Threats](https://rules.emergingthreats.net/) | IP | Compromised hosts |

All sources are free and require no API keys.

## Requirements

- Go 1.22 or later

## Getting Started

```bash
# Clone the repository
git clone https://github.com/0x-singularity/astra-threat-feed
cd astra-threat-feed

# Install dependencies
make tidy

# Copy and edit the config
cp config.example.yaml config.yaml

# Fetch IOCs and generate the MISP feed in one step
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
  org_uuid: ""              # Leave empty to auto-generate

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

## Repository Layout

```
astra-threat-feed/
├── cmd/astra-feed/         CLI entrypoint
├── internal/
│   ├── config/             YAML config loading
│   ├── database/           SQLite storage and deduplication
│   ├── feeds/              One file per feed source
│   ├── ioc/                IOC type definitions
│   └── misp/               MISP event and manifest generation
├── config.example.yaml     Annotated example config
└── Makefile                Common tasks (build, sync, clean, etc.)
```

## MISP Feed Structure

After running `sync` or `generate`, the `output/` directory contains:

```
output/
├── manifest.json           # Event index consumed by MISP
├── <uuid>.json             # One event file per feed source
└── ...
```

Each feed source maps to a single MISP event with a stable UUID. Subsequent
runs update the event file in place rather than creating new ones, keeping the
feed size predictable.

## Hosting the Feed

### GitHub Pages

Push the `output/` directory (or a dedicated `gh-pages` branch) and enable
GitHub Pages for that path. MISP instances can then subscribe to:

```
https://<user>.github.io/<repo>/
```

### Any Web Server

Serve the `output/` directory as static files. MISP requires the server to
return `Content-Type: application/json` for `.json` files; most servers handle
this automatically.

### Adding the Feed to MISP

In your MISP instance, go to **Sync Actions > List Feeds > Add Feed** and
enter the URL pointing to the `output/` directory. Set the format to
**MISP Feed**.

## Automating Updates

Use cron to keep the feed current. For example, to sync every six hours:

```cron
0 */6 * * * cd /path/to/astra-threat-feed && ./astra-feed sync >> /var/log/astra-feed.log 2>&1
```

## Contributing

Contributions are welcome. To add a new feed source:

1. Create `internal/feeds/<name>.go` implementing the `feeds.Feed` interface.
2. Register it in `internal/feeds/feed.go` inside `All()`.
3. Add the corresponding config fields to `internal/config/config.go` and `config.example.yaml`.
4. Add feed metadata (event info, threat level, tags) to `feedMetadata` in `internal/misp/generator.go`.
5. Open a pull request with a brief description of the source and any licensing considerations.

Please ensure any new feed source is freely accessible without account registration.

## License

MIT
