BINARY   := astra-feed
CMD      := ./cmd/astra-feed
LDFLAGS  := -s -w

.PHONY: build tidy sync fetch generate stats clean test

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

tidy:
	go mod tidy

sync: build
	./$(BINARY) sync

fetch: build
	./$(BINARY) fetch

generate: build
	./$(BINARY) generate

stats: build
	./$(BINARY) stats

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -rf output/
