MOCK_FILES = mockapi/mockapi.go mockmetrics/mockmetrics.go mocksigner/mocksigner.go

all: $(MOCK_FILES)

mockapi/mockapi.go: ../api/api.go
	go run github.com/golang/mock/mockgen --destination $@ --package mockapi --mock_names Log=MockLog,Secondary=MockSecondary,Witness=MockWitness sigsum.org/sigsum-go/pkg/api Log,Secondary,Witness

mockmetrics/mockmetrics.go: ../server/config.go
	go run github.com/golang/mock/mockgen --destination $@ --package mockmetrics sigsum.org/sigsum-go/pkg/server Metrics

mocksigner/mocksigner.go: ../crypto/crypto.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocksigner sigsum.org/sigsum-go/pkg/crypto Signer

clean:
	rm -f $(MOCK_FILES)

.PHONY: clean
