DATE := $(shell date +"%B %Y")
VERSION := $(shell git describe --tags --always)

default: doc

check: mocks
	go build ./...
	go test ./...
	cd tests && $(MAKE) check

mocks:
	cd pkg/mocks && $(MAKE)

doc:
	doc/help2man/generate $(VERSION)
	pandoc doc/tools.md -s -t man -o doc/sigsum-tools.7 \
		-M title="sigsum-tools" \
		-M section="7" \
		-M header="User guide" \
		-M footer="sigsum-tools $(VERSION)" \
		-M date="$(DATE)"

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean

.PHONY: default check clean doc mocks
