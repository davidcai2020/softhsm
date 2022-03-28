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

const (
	Version    = "1.0"
	Algorithm  = "AES"
	Bitslength = 256
	Mode       = "GCM"
)

func testEncryptDecrypt(client pb.CryptoServiceClient, ctx context.Context) {

	log.Printf("------ test encrypt ------\n")

	plaintext := "Hello cryptoServicer!"
	log.Printf("encrypting plaintext: %s\n", plaintext)

	// test encrypt
	buf := []byte(plaintext)
	encryptRequest := &pb.CryptoRequest{
		Version: Version,
		KeyType: pb.CryptoRequest_KEY_TYPE_ENCRYPTION,
		KeyInfo: &pb.CryptoRequest_KeyInfo{
			Algorithm:  Algorithm,
			Bitslength: Bitslength,
			Mode:       Mode},
		InputBuffer:     buf,
		InputBufferSize: int32(len(buf))}

	reply, err := client.SSMEncrypt(ctx, encryptRequest)
	if err != nil {
		log.Printf("grpc error: %v\n", err)
		return
	} else if reply.Status != 0 {
		log.Printf("SSMEncrypt() failed: code(%d), errmsg(%s)\n", reply.Status, string(reply.GetOutputBuffer()))
		return
	}
	log.Printf("encryptReply: %+v\n", *reply)

	// test decrypt
	log.Printf("\n------ test decrypt ------\n")
	ciphertext_with_iv := reply.GetOutputBuffer()
	ciphertextSize := reply.GetOutputBufferSize()
	log.Printf("decrypting ciphertext: %x\n", ciphertext_with_iv)
	decryptRequest := &pb.CryptoRequest{
		Version: Version,
		KeyType: pb.CryptoRequest_KEY_TYPE_DECRYPTION,
		KeyInfo: &pb.CryptoRequest_KeyInfo{
			Algorithm:  Algorithm,
			Bitslength: Bitslength,
			Mode:       Mode},
		InputBuffer:     ciphertext_with_iv,
		InputBufferSize: ciphertextSize}

	reply, err = client.SSMDecrypt(ctx, decryptRequest)
	if err != nil {
		log.Printf("grpc error: %v\n", err)
		return
	} else if reply.Status != 0 {
		log.Printf("SSMDecrypt() failed: code=%d, errmsg=%s\n", reply.Status, string(reply.GetOutputBuffer()))
		return
	}
	log.Printf("decryptReply: %+v\n", *reply)
	decryptedText := string(reply.GetOutputBuffer())

	log.Printf("original = %s, decrypted = %s\n", plaintext, decryptedText)
	if plaintext == decryptedText {
		log.Printf("Test PASS")
	} else {
		log.Printf("Test Failed")
	}
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
	log.Printf("conn = %+v\n", conn)
	defer conn.Close()
	cryptoClient := pb.NewCryptoServiceClient(conn)
	log.Printf("cryptoClient = %+v\n", cryptoClient)

	// Contact cryptoService server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	testEncryptDecrypt(cryptoClient, ctx)
}
