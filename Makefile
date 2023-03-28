# Let the go tool manage dependencies.
all:
	go build ./...

mocks:
	cd pkg/mocks && $(MAKE)

check: mocks
	go test ./...
	cd tests && $(MAKE) check

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean

.PHONY: all check clean mocks
