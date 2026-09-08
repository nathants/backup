.PHONY: check test docker-test aws-contract r2-contract fuzz

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

check:
	gofmt -w cmd internal integration
	git diff HEAD --check
	go test ./...
	go test -race ./...
	go vet ./...

test:
	go test ./...

fuzz:
	@set -eu; \
	for target in $(FUZZ_TARGETS); do \
		package=$${target%%:*}; name=$${target#*:}; \
		echo "fuzz $$package $$name"; \
		go test "$$package" -run='^$$' -fuzz="^$$name$$" -fuzztime="$(FUZZ_TIME)"; \
	done

docker-test:
	BACKUP_DOCKER_TEST=1 go test ./integration -count=1 -v

aws-contract:
	BACKUP_AWS_CONTRACT=1 go test ./integration -run '^TestAWSCloudContract$$' -count=1 -v

r2-contract:
	BACKUP_R2_CONTRACT=1 go test ./integration -run '^TestCloudflareR2Contract$$' -count=1 -v
