# Populate VERSION and DATE based on the latest git-commit.  The user may
# override VERSION and DATE by specifying *both* on the command line.
#
# Note: these variables are only used for generating man pages.
VERSION ?= $(shell git describe --tags --always)
ifeq ($(origin VERSION), file)
	COMMIT := $(shell git rev-parse $(VERSION))
	# The timestamp git-show extracts is in the *author's timezone*, i.e.,
	# there's no conversion to the *user's timezone* unless --date=local is
	# provided.  So, we can be sure we have a deterministic timestamp value.
	# We're using the timestamp that was explicitly set by the author (%ad).
	#
	# %B uses the *user's locale* when printing the month because the date
	# formatting is done by strftime (see man git-log and man strftime).  To
	# ensure a deterministic value, we use the standard locale called "C".
	# https://www.gnu.org/software/libc/manual/html_node/Choosing-Locale.html
	#
	# We use LC_ALL because it ensures we override both LANG and LC_TIME.
	# https://www.gnu.org/software/libc/manual/html_node/Locale-Categories.html
	TIMESTAMP := $(shell LC_ALL=C git show -s --format=%ad --date=format:"%B %Y" $(COMMIT))
endif
DATE ?= $(TIMESTAMP)

default: doc

check: mocks
	go build ./...
	go test ./...
	cd tests && $(MAKE) check

mocks:
	cd pkg/mocks && $(MAKE)

doc:
	doc/help2man/generate $(VERSION)
	pandoc doc/tools.md -s -t man -o doc/sigsum-tools.7 \
		-M title="sigsum-tools" \
		-M section="7" \
		-M header="User guide" \
		-M footer="sigsum-tools $(VERSION)" \
		-M date="$(DATE)"

clean:
	cd tests && $(MAKE) clean
	cd pkg/mocks && $(MAKE) clean

.PHONY: default check clean doc mocks
