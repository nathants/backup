.DEFAULT_GOAL := build
.PHONY: build check check-lint integration integration-git-remote fuzz

build:
	go build -o backup ./cmd/backup

FUZZ_TARGETS := \
	./internal/backup:FuzzRepairDataPartRecords \
	./internal/format:FuzzCanonicalMetadataParsers \
	./internal/format:FuzzValidatePath \
	./internal/format:FuzzCanonicalObjectKeys \
	./internal/localconfig:FuzzTrustedConfigParser \
	./internal/objectstore:FuzzObjectIdentityAndLogicalKeys \
	./internal/pack:FuzzCanonicalTarReader \
	./internal/pack:FuzzEncryptedPackReader \
	./internal/pack:FuzzAuthenticatedPackReader \
	./internal/s3server:FuzzRequestTargetGrammar \
	./internal/s3server:FuzzCanonicalQuery
FUZZ_TIME ?= 10s
CLOUD_FREE_ENV := ./integration/cloud-free-env.sh

check: check-lint
	$(CLOUD_FREE_ENV) go test -timeout=30m -cover ./...
	$(CLOUD_FREE_ENV) go test -timeout=30m -race ./...

check-lint:
	bash -n integration/*.sh
	git diff HEAD --check
	@command -v libcheck >/dev/null || { echo 'libcheck not found; install it with: go install github.com/nathants/libcheck@latest' >&2; exit 1; }
	libcheck check

integration: check
	./integration/run.sh

integration-git-remote: check
	./integration/git-remote.sh

fuzz:
	@set -eu; \
	for target in $(FUZZ_TARGETS); do \
		package=$${target%%:*}; name=$${target#*:}; \
		echo "fuzz $$package $$name"; \
		go test "$$package" -run='^$$' -fuzz="^$$name$$" -fuzztime="$(FUZZ_TIME)"; \
	done
