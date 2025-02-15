PROGRAMS=sigsum-key sigsum-submit sigsum-verify sigsum-token

build: $(PROGRAMS:%=build-%)
build-%:
	mkdir -p build
	go build -o build/$* cmd/$*/$*.go
	help2man \
		--no-info \
		--include=cmd/$*/help2man/name.help2man \
		--include=cmd/$*/help2man/see-also.help2man \
		--include=doc/help2man/return-codes.help2man \
		--include=doc/help2man/reporting-bugs.help2man \
		--include=doc/help2man/contact.help2man \
		-o build/$*.1 cmd/$*/help2man/wrapper

mocks:
	cd pkg/mocks && $(MAKE)

check: mocks
	go build ./...
	go test ./...
	cd tests && $(MAKE) check

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean
	rm -rf build

.PHONY: all check clean mocks
