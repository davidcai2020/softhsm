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
		log.Printf("getRandom failed: code=%d, errmsg=%s\n", reply.Status, string(reply.GetOutputBuffer()))
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

	// Load client's certificate and private key
	cliCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("failed to load client certificate & private key: %v", err)
	}
	log.Printf("successfully load client certificate & private key.\n")

	// load client CA
	cacert := cfgPath + "/" + cliCfg.CACert
	log.Printf("cacert = %s\n", cacert)
	cliCA, err := ioutil.ReadFile(cacert)
	if err != nil {
		log.Fatalf("failed to load client CA: %v", err)
	}
	log.Printf("successfully load client CA.\n")

	// add client CA
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(cliCA) {
		log.Fatalf("failed to add client CA: %v", err)
	}
	log.Printf("successfully add client CA.\n")

	// Create the credentials
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		Certificates:       []tls.Certificate{cliCert},
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
