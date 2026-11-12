# Contributing

Go 1.23 or newer is required. No third-party runtime dependencies are used.

```sh
go test -race ./...
go vet ./...
python3 -m unittest discover -s tests -v
gofmt -w cmd internal
go test ./internal/mask -fuzz=FuzzMask -fuzztime=10s
```

Use synthetic test data only. For a detector change, add false-positive and
false-negative regression cases. Document its scope and limitations in README.md.
Keep stdout exclusively for masked content and explicit version output.
Errors must not include input fragments, matched values, or custom rule contents.
