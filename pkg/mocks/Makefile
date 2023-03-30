MOCK_FILES = client.go
all: $(MOCK_FILES)

client.go: ../client/client.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocks --mock_names Log=MockLogClient sigsum.org/sigsum-go/pkg/client Log

clean:
	rm -f $(MOCK_FILES)

.PHONY: clean
