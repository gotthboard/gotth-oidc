.PHONY: verify

verify:
	version="$$(go env GOVERSION)"; test "$${version%%-*}" = "go1.26.6"
	test -z "$$(gofmt -l $$(git ls-files --cached --others --exclude-standard -- '*.go'))"
	sh scripts/check-public-api.sh
	sh scripts/check-release-tooling.sh
	go vet -mod=readonly ./...
	go test -mod=readonly -race -cover ./...
