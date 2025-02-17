PROGRAMS=sigsum-key sigsum-submit sigsum-verify sigsum-token
VERSION ?= $(shell git describe --tags --always)

build: $(PROGRAMS:%=build-%)
build-%:
	help2man \
		--no-info --version-string "sigsum-submit (sigsum-go module) git $(VERSION)" \
		--include=cmd/$*/name.help2man \
		--include=cmd/$*/see-also.help2man \
		--include=doc/help2man/return-codes.help2man \
		--include=doc/help2man/reporting-bugs.help2man \
		--include=doc/help2man/contact.help2man \
		-o cmd/$*/$*.1 "doc/help2man/wrapper $*"

mocks:
	cd pkg/mocks && $(MAKE)

check: mocks
	go build ./...
	go test ./...
	cd tests && $(MAKE) check

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean

.PHONY: all check clean mocks
