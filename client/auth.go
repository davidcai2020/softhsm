package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	util "softhsm/client/utils"
)

func mtlsConnect(cliCfg *util.ClientCfg, cfgPath string) *grpc.ClientConn {
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

	return conn
}
