TESTS = ssh-agent-test \
	sign-verify-test sign-agent-test \
	keyhash-test keyhex-test help-msg-test \
	token-record-test token-create-raw-test token-create-header-test \
	sigsum-submit-test sigsum-submit-batch-test \
	witness-get-tree-size-test witness-add-tree-head-test \
	sigsum-submit-witness-test
all:

check:
	./run-tests $(TESTS)

clean:
	rm -rf bin test.*

.PHONY: all check clean
