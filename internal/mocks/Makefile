MOCK_FILES = roundtripper.go

all: $(MOCK_FILES)

roundtripper.go:
	go run github.com/golang/mock/mockgen --destination $@ --package mocks net/http RoundTripper

clean:
	rm -f $(MOCK_FILES)

.PHONY: clean
