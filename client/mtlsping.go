package main

import (
	"context"
	"log"
	"time"

	util "softhsm/client/utils"
	pb "softhsm/grpclib"
)

var (
	loop = 3
)

// call SSMPing
func ping(client pb.CryptoServiceClient, ctx context.Context, host string) {
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
func ssmping(client pb.CryptoServiceClient, ctx context.Context, host string) {
	log.Printf("Ping %s:\n", host)
	for i := 0; i < loop; i++ {
		ping(client, ctx, host)
	}
}

func main() {
	// Parsing environment variables
	cliCfg, cfgPath, err := util.GetConf()
	if err != nil {
		log.Fatalf("GetConf() failed: %v", err)
	}

	conn := mtlsConnect(cliCfg, cfgPath)
	defer conn.Close()

	cryptoClient := pb.NewCryptoServiceClient(conn)

	// Contact cryptoService server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ssmping(cryptoClient, ctx, cliCfg.Host)
}
