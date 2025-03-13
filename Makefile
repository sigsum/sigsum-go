# Populate VERSION and DATE based on the latest git-commit.  The user may
# override VERSION and DATE by specifying *both* on the command line.
#
# Note: these variables are only used for generating man pages.
VERSION ?= $(shell git describe --tags --always)
ifeq ($(origin VERSION), file)
	COMMIT := $(shell git rev-parse $(VERSION))
	TIMESTAMP := $(shell git show -s --format=%cd --date=format:"%B %Y" $(COMMIT))
endif
DATE ?= $(TIMESTAMP)

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
