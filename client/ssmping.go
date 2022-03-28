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

	ssmping(cryptoClient, ctx)
}
