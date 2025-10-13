// module name: 0xgen
module github.com/RowanDark/Glyph

go 1.24.3

require (
	github.com/inconshreveable/go-update v0.0.0-20160112193335-8152e7eb6ccf
	github.com/kr/binarydist v0.1.0
	golang.org/x/net v0.41.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.9
)

require (
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/crypto => ./third_party/golang.org/x/crypto
