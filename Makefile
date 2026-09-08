.PHONY: check check-deps check-lint integration fuzz

FUZZ_TARGETS := \
	./internal/format:FuzzCanonicalMetadataParsers \
	./internal/format:FuzzValidatePath \
	./internal/format:FuzzCanonicalObjectKeys \
	./internal/localconfig:FuzzTrustedConfigParser \
	./internal/objectstore:FuzzObjectIdentityAndLogicalKeys \
	./internal/pack:FuzzCanonicalTarReader \
	./internal/pack:FuzzEncryptedPackReader \
	./internal/s3server:FuzzRequestTargetGrammar \
	./internal/s3server:FuzzCanonicalQuery
FUZZ_TIME ?= 10s
CLOUD_FREE_ENV := ./integration/cloud-free-env.sh
LINT_TOOLS := staticcheck ineffassign errcheck bodyclose nargs

check: check-lint
	$(CLOUD_FREE_ENV) go test -cover ./...
	$(CLOUD_FREE_ENV) go test -race ./...

check-deps:
	@for tool in $(LINT_TOOLS); do \
		command -v "$$tool" >/dev/null || { printf 'missing required check tool: %s\n' "$$tool" >&2; exit 1; }; \
	done

check-lint: check-deps
	bash -n integration/*.sh
	@files="$$(find cmd internal integration -type f -name '*.go' -print0 | xargs -0 -r gofmt -l)"; \
		if [ -n "$$files" ]; then printf 'unformatted Go files:\n%s\n' "$$files" >&2; exit 1; fi
	git diff HEAD --check
	$(CLOUD_FREE_ENV) staticcheck ./...
	$(CLOUD_FREE_ENV) ineffassign ./...
	$(CLOUD_FREE_ENV) errcheck ./...
	$(CLOUD_FREE_ENV) go vet -vettool="$$(command -v bodyclose)" ./...
	$(CLOUD_FREE_ENV) nargs ./...
	$(CLOUD_FREE_ENV) go vet ./...

integration: check
	./integration/run.sh

fuzz:
	@set -eu; \
	for target in $(FUZZ_TARGETS); do \
		package=$${target%%:*}; name=$${target#*:}; \
		echo "fuzz $$package $$name"; \
		go test "$$package" -run='^$$' -fuzz="^$$name$$" -fuzztime="$(FUZZ_TIME)"; \
	done
