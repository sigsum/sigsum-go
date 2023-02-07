# Let the go tool manage dependencies.
all:
	go build ./...

check:
	go test ./...
	cd tests && $(MAKE) check

clean:
	cd tests && $(MAKE) clean

.PHONY: all check clean
