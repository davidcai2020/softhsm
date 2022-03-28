package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	util "softhsm/client/utils"
	pb "softhsm/grpclib"
)

// call SSMGetRandom to get random
func getRandom(client pb.CryptoServiceClient, ctx context.Context, size int32) {
	// init random number request structure
	request := &pb.RandomRequest{
		Version:    "1.0",
		RandomSize: int32(size)}

	// get random number
	reply, err := client.SSMGetRandom(ctx, request)
	if err != nil {
		log.Printf("grpc error: %v\n", err)
	} else if reply.Status != 0 {
		log.Printf("getRandom() failed: code=%d, errmsg=%s\n", reply.Status, string(reply.GetOutputBuffer()))
	} else {
		log.Printf("random size: %d, random: %x\n", reply.GetOutputBufferSize(), reply.GetOutputBuffer())
	}
}

// testcases
func testRandom(client pb.CryptoServiceClient, ctx context.Context) {
	// test valid: only support 32 bytes
	log.Printf("test 1: valid random size 32:\n")
	getRandom(client, ctx, 32)

	// test invalid: any size != 32
	log.Printf("test 2: invalid random size 16:\n")
	getRandom(client, ctx, 16)
}

func main() {
	// Parsing environment variables
	cliCfg, cfgPath, err := util.GetConf()
	if err != nil {
		log.Fatalf("GetConf() failed: %v", err)
	}

	addr := fmt.Sprintf("%s:%s", cliCfg.Host, cliCfg.Port)
	log.Printf("addr = %s\n", addr)

	// load certificate
	cert := cfgPath + "/" + cliCfg.Cert
	log.Printf("cert = %s\n", cert)
	key := cfgPath + "/" + cliCfg.Key
	log.Printf("key = %s\n", key)
	mine, err := ioutil.ReadFile(cert)
	if err != nil {
		log.Fatalf("failed to load certificate: %v", err)
	}
	cp, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal("failed to get system certificate pool")
	}
	if !cp.AppendCertsFromPEM(mine) {
		log.Fatalf("failed to append certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            cp,
	}

	// Set up a connection to cryptoService TLS server.
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoServiceClient(conn)

	// Contact cryptoService server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	testRandom(cryptoClient, ctx)
}
