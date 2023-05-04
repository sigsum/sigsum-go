MOCK_FILES = client.go
all: $(MOCK_FILES)

client.go: ../client/client.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocks --mock_names Log=MockLogClient,Secondary=MockSecondaryClient,Witness=MockWitnessClient sigsum.org/sigsum-go/pkg/client Log,Secondary,Witness

clean:
	rm -f $(MOCK_FILES)

.PHONY: clean
