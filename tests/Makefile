TESTS = ssh-agent-test \
	sign-verify-test sign-agent-test \
	keyhash-test keyhex-test key-vkey-test \
	help-msg-test version-msg-test \
	token-record-test token-create-raw-test token-create-header-test \
	sigsum-submit-test sigsum-submit-batch-test \
	sigsum-submit-namedpolicy-test \
	witness-add-checkpoint-test \
	sigsum-submit-witness-test
all:

check:
	./run-tests $(TESTS)

clean:
	rm -rf bin test.*

.PHONY: all check clean
