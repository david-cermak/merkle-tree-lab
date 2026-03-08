module github.com/merkle-tree-lab

go 1.25.0

replace github.com/google/trillian => ./impl/trillian

require (
	github.com/google/trillian v0.0.0
	github.com/transparency-dev/merkle v0.0.2
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
