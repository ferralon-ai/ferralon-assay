module github.com/ferralon-ai/ferralon-assay/plugins/cfamily

go 1.26.3

require (
	github.com/ferralon-ai/cgx/sdk/go v0.0.0-20261013083326-408aaf273779
	github.com/ferralon-ai/ferralon-assay v0.0.0-00010101000000-000000000000
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/ferralon-ai/ferralon-assay => ../..
