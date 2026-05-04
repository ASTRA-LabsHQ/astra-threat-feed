package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/config"
	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/database"
	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/feeds"
	"github.com/ASTRA-LabsHQ/astra-threat-feed/internal/misp"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatalf("config: %v", err)
	}

	db, err := database.Open(cfg.Database.Path)
	if err != nil {
		fatalf("database: %v", err)
	}
	defer db.Close()

	switch flag.Arg(0) {
	case "fetch":
		runFetch(cfg, db)
	case "generate":
		runGenerate(cfg, db)
	case "sync":
		runFetch(cfg, db)
		runGenerate(cfg, db)
	case "stats":
		runStats(db)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", flag.Arg(0))
		usage()
		os.Exit(1)
	}
}

func runFetch(cfg *config.Config, db *database.DB) {
	fmt.Println("Fetching IOCs from feeds...")
	active := feeds.All(cfg)
	if len(active) == 0 {
		fmt.Println("No feeds enabled. Check your config.yaml.")
		return
	}

	for _, feed := range active {
		fmt.Printf("  [%s] fetching...\n", feed.Name())
		items, err := feed.Fetch()
		if err != nil {
			fmt.Printf("  [%s] error: %v\n", feed.Name(), err)
			_ = db.LogSync(feed.Name(), 0, "error", err.Error())
			continue
		}
		count, err := db.UpsertIOCs(items)
		if err != nil {
			fmt.Printf("  [%s] db error: %v\n", feed.Name(), err)
			_ = db.LogSync(feed.Name(), 0, "error", err.Error())
			continue
		}
		fmt.Printf("  [%s] processed %d IOCs\n", feed.Name(), count)
		_ = db.LogSync(feed.Name(), count, "ok", "")
	}
	fmt.Println("Fetch complete.")
}

func runGenerate(cfg *config.Config, db *database.DB) {
	fmt.Println("Generating MISP feed files...")
	gen := misp.NewGenerator(cfg, db)
	if err := gen.Generate(); err != nil {
		fatalf("generate: %v", err)
	}
	fmt.Printf("Output written to %s\n", cfg.Output.Path)
}

func runStats(db *database.DB) {
	stats, err := db.Stats()
	if err != nil {
		fatalf("stats: %v", err)
	}

	fmt.Printf("Total IOCs: %d\n\n", stats.TotalIOCs)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tCOUNT")
	fmt.Fprintln(w, "----\t-----")
	for _, t := range []string{"ip-dst", "domain", "md5", "sha1", "sha256"} {
		if n, ok := stats.ByType[t]; ok {
			fmt.Fprintf(w, "%s\t%d\n", t, n)
		}
	}
	w.Flush()

	fmt.Println()
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tCOUNT")
	fmt.Fprintln(w, "------\t-----")
	for src, n := range stats.BySource {
		fmt.Fprintf(w, "%s\t%d\n", src, n)
	}
	w.Flush()

	if stats.LastSyncedAt != nil {
		fmt.Printf("\nLast sync: %s\n", stats.LastSyncedAt.Format("2006-01-02 15:04:05 UTC"))
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: astra-feed [options] <command>

Commands:
  sync      Fetch IOCs from all feeds then generate MISP files
  fetch     Fetch IOCs from all feeds and store in the database
  generate  Generate MISP feed files from the database
  stats     Print database statistics

Options:
  -config string   Path to config file (default: "config.yaml")
`)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
