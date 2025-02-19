default: doc

check: mocks
	go build ./...
	go test ./...
	cd tests && $(MAKE) check

mocks:
	cd pkg/mocks && $(MAKE)

doc:
	doc/help2man/generate

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean

.PHONY: default check clean doc mocks
