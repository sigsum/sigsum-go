# Let the go tool manage dependencies.
all:
	go build ./...

check:
	go test ./...
	cd tests && $(MAKE) check

.PHONY: all check
