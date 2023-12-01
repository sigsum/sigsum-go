MOCK_FILES = api.go metrics.go

all: $(MOCK_FILES)

api.go: ../api/api.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocks --mock_names Log=MockLog,Secondary=MockSecondary,Witness=MockWitness sigsum.org/sigsum-go/pkg/api Log,Secondary,Witness

metrics.go: ../server/config.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocks sigsum.org/sigsum-go/pkg/server Metrics


clean:
	rm -f $(MOCK_FILES)

.PHONY: clean
