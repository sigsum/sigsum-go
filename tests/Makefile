TESTS = ssh-agent-test \
	sign-verify-test sign-agent-test \
	sign-ssh-interop-test verify-ssh-interop-test \
	keyhash-test keyhex-test help-msg-test \
	token-record-test token-create-raw-test token-create-header-test \
	sigsum-submit-test
all:

check:
	./run-tests $(TESTS)

clean:
	rm -rf bin test.*

.PHONY: all check clean
