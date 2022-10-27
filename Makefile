# Let the go tool manage dependencies.
all:
	go build ./...

check:
	go test ./...

.PHONY: all check
