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

var (
	loop = 3
	host string
)

// call SSMPing
func ping(client pb.CryptoServiceClient, ctx context.Context) {
	// init ping request structure
	request := &pb.EmptyRequest{}

	// ping
	start := time.Now()
	reply, err := client.SSMPing(ctx, request)
	if err != nil {
		log.Printf("grpc error: %v\n", err)
	} else if reply.Status != 0 {
		log.Printf("ping() failed: code=%d, errmsg=%s\n", reply.Status, string(reply.GetOutputBuffer()))
	} else {
		end := time.Now()
		elapsed := end.Sub(start)
		datasize := reply.OutputBufferSize
		log.Printf("%d bytes from %s: time=%v\n", datasize, host, elapsed)
	}
}

// ping function
func ssmping(client pb.CryptoServiceClient, ctx context.Context) {
	log.Printf("Ping %s:\n", host)
	for i := 0; i < loop; i++ {
		ping(client, ctx)
	}
}

func main() {
	// Parsing environment variables
	cliCfg, cfgPath, err := util.GetConf()
	if err != nil {
		log.Fatalf("GetConf() failed: %v", err)
	}

	host = cliCfg.Host
	addr := fmt.Sprintf("%s:%s", host, cliCfg.Port)
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

	ssmping(cryptoClient, ctx)
}
