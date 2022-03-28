# softhsm
Software Security Module (SSM)

Implemented in Go utilizing gRPC and protobufs.

Uses Go crypto.

Contains 1 module: CryptoService.

The CCM calls the CryptoService's SSM functions, and consumes the results.

Functions:

SSMEncrypt

SSMDecrypt

SSMGetRandom

The environmental variables required:

export GOPATH=$HOME/go

export SSM_CONFIG_PATH=$GOPATH/src/softhsm/ssm/cfg

export CLIENT_CONFIG_PATH=$GOPATH/src/softhsm/client/cfg

To enable Mutually-Authenticated TLS for gRPC (assuming a 1-level PKI hierarchy for now):

Use the OVHCloud KMS Demo CA certificate, $HOME/go/src/softhsm/client/cfg/OVHCloud.KMS.Demo.CA.crt

(For now) use my TLS Server SSM private-key and associated OVH-CA-issued TLS Server SSM certificate,
$HOME/go/src/softhsm/ssm/cfg/ssmkey.pem and $HOME/go/src/softhsm/ssm/cfg/ssmcert.crt respectively.

(For now) use my TLS Client private-key and associated OVH-CA-issued TLS Client certificate,
$HOME/go/src/softhsm/client/cfg/ccmkey.pem and $HOME/go/src/softhsm/ccm/cfg/ccmcert.crt respectively.

First, generate the grpc and protocol buffer files:

cd $HOME/go/src/softhsm/

protoc --go_out=. grpclib/cryptoService.proto 

protoc --go-grpc_out=. grpclib/cryptoService.proto

Then add the required Go modules:

go mod init

go mod tidy

Next, build and run the crypto service (on localhost 127.0.0.1:8888 on Mac):

go run ssm/cryptoService.go

Instead, to cross-build for Linux (for service on 0.0.0.0:8888):

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ssm/cryptoService.go

The above command builds the Linux executable ./cryptoService

To test (on another console):  

go run client/testCrypt.go

go run client/testRandom.go

go run client/ssmping.go
