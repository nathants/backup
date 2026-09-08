.PHONY: check integration fuzz

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

check:
	bash -n integration/*.sh
	@files="$$(find cmd internal integration -type f -name '*.go' -print0 | xargs -0 -r gofmt -l)"; \
		if [ -n "$$files" ]; then printf 'unformatted Go files:\n%s\n' "$$files" >&2; exit 1; fi
	git diff HEAD --check
	$(CLOUD_FREE_ENV) go test -cover ./...
	$(CLOUD_FREE_ENV) go test -race ./...
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
