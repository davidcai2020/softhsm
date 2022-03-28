package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "softhsm/grpclib"
	util "softhsm/ssm/utils"
)

const (
	FixedRandomSize = 32
	MinBlocksize    = 16
	MaxBlocksize    = 4096
)

var (
	// DREK encryption/decryption key
	keyDREK = []byte("01234567890123456789012345678901")
)

// server
type cryptoServiceServer struct {
	pb.UnimplementedCryptoServiceServer
}

// reply in case of error
func ErrorReply(code int32, err string) (*pb.SSMReply, error) {
	if code == 0 {
		// incorrect error code
		code = -1
	}
	outputbuf := []byte(err)
	return &pb.SSMReply{
		Status:           code,
		OutputBuffer:     outputbuf,
		OutputBufferSize: int32(len(outputbuf))}, nil
}

// reply in case of error
func cryptoErrorReply(code int32, err string) (*pb.SSMReply, error) {
	return ErrorReply(code, err)
}

func isValidBlocksize(bufsize int32) bool {
	return bufsize >= MinBlocksize && bufsize <= MaxBlocksize
}

// aes gcm encrypt
func gcmEncrypt(blk cipher.Block, in *pb.CryptoRequest) (*pb.SSMReply, error) {
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	// create nonce
	log.Printf("NonceSize = %d\n", gcm.NonceSize())
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	// check whether buffer is valid
	log.Printf("InputBufsize = %d\n", in.GetInputBufferSize())
	if !isValidBlocksize(in.GetInputBufferSize()) {
		return cryptoErrorReply(-1, "input buffer out of bounds")
	}

	ciphertext := gcm.Seal(nonce, nonce, in.GetInputBuffer(), nil)

	return &pb.SSMReply{
		Status:           0,
		OutputBuffer:     ciphertext,
		OutputBufferSize: int32(len(ciphertext))}, nil
}

// aes gcm decrypt
func gcmDecrypt(blk cipher.Block, in *pb.CryptoRequest) (*pb.SSMReply, error) {
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	ciphertext := in.GetInputBuffer()
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return cryptoErrorReply(-1, "invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	// check whether buffer is valid
	log.Printf("InputBufsize = %d\n", in.GetInputBufferSize())
	if !isValidBlocksize(in.GetInputBufferSize()) {
		return cryptoErrorReply(-1, "input buffer out of bounds")
	}

	return &pb.SSMReply{
		Status:           0,
		OutputBuffer:     []byte(plaintext),
		OutputBufferSize: int32(len(plaintext))}, nil
}

// SSMEncrypt implements cryptoService encrypt
func (s *cryptoServiceServer) SSMEncrypt(ctx context.Context, in *pb.CryptoRequest) (*pb.SSMReply, error) {
	if in.GetKeyType() != pb.CryptoRequest_KEY_TYPE_ENCRYPTION {
		return cryptoErrorReply(-1, "key_name not matched")
	}

	if strings.ToLower(in.GetKeyInfo().GetAlgorithm()) != "aes" {
		return cryptoErrorReply(-1, "not supported algorithm")
	}

	// AES cipher: 256
	n := in.GetKeyInfo().GetBitslength()
	if n != 256 {
		return cryptoErrorReply(-1, "key_size not supported")
	}
	blk, err := aes.NewCipher(keyDREK)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	// only GCM is supported.
	if strings.ToLower(in.GetKeyInfo().GetMode()) != "gcm" {
		return cryptoErrorReply(-1, "mode not supported")
	}

	return gcmEncrypt(blk, in)
}

// SSMDecrypt implements cryptoService decrypt
func (s *cryptoServiceServer) SSMDecrypt(ctx context.Context, in *pb.CryptoRequest) (*pb.SSMReply, error) {
	if in.GetKeyType() != pb.CryptoRequest_KEY_TYPE_DECRYPTION {
		return cryptoErrorReply(-1, "key_name not matched")
	}

	if strings.ToLower(in.GetKeyInfo().GetAlgorithm()) != "aes" {
		return cryptoErrorReply(-1, "not supported algorithm")
	}

	// AES cipher: 256
	n := in.GetKeyInfo().GetBitslength()
	if n != 256 {
		return cryptoErrorReply(-1, "key_size not supported")
	}
	blk, err := aes.NewCipher(keyDREK)
	if err != nil {
		return cryptoErrorReply(-1, err.Error())
	}

	// only GCM is supported.
	if strings.ToLower(in.GetKeyInfo().GetMode()) != "gcm" {
		return cryptoErrorReply(-1, "mode not supported")
	}

	return gcmDecrypt(blk, in)
}

//  SSMGetRandomNumber implements cryptoService GetRandomNumber
func (s *cryptoServiceServer) SSMGetRandom(ctx context.Context, in *pb.RandomRequest) (*pb.SSMReply, error) {
	if in.GetRandomSize() != FixedRandomSize {
		return ErrorReply(-1, "random_size not supported")
	}

	// create nonce
	nonce := make([]byte, in.GetRandomSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return ErrorReply(-1, err.Error())
	}

	return &pb.SSMReply{
		Status:           0,
		OutputBuffer:     nonce,
		OutputBufferSize: in.GetRandomSize()}, nil
}

// ping
func (s *cryptoServiceServer) SSMPing(ctx context.Context, in *pb.EmptyRequest) (*pb.SSMReply, error) {
	data := []byte(time.Now().String())
	return &pb.SSMReply{
		Status:           0,
		OutputBuffer:     data,
		OutputBufferSize: int32(len(data))}, nil
}

func launchServer(svrCfg *util.ServerCfg, cfgPath string) {
	addr := fmt.Sprintf("%s:%s", "0.0.0.0", svrCfg.Port)
	log.Printf("addr = %s\n", addr)

	// load svr cert & key
	cert := cfgPath + "/" + svrCfg.Cert
	log.Printf("cert = %s\n", cert)
	key := cfgPath + "/" + svrCfg.Key
	log.Printf("key = %s\n", key)
	svrCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("failed to load svr cert & key: %v", err)
	}
	log.Printf("successfully load svr cert & key.\n")

	// load svr CA
	cacert := cfgPath + "/" + svrCfg.CACert
	log.Printf("cacert = %s\n", cacert)
	svrCA, err := ioutil.ReadFile(cacert)
	if err != nil {
		log.Fatalf("failed to svr CA: %v", err)
	}
	log.Printf("successfully load svr CA.\n")

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(svrCA) {
		log.Fatalf("failed to add svr CA's certificate")
	}
	log.Printf("successfully add svr CA.\n")

	config := &tls.Config{
		Certificates: []tls.Certificate{svrCert},
		//ClientAuth:   tls.RequireAndVerifyClientCert,
		RootCAs: cp,
	}

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(config)))
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// regiester cryptoServiceServer
	pb.RegisterCryptoServiceServer(s, &cryptoServiceServer{})

	log.Printf("cryptoServicer listening at tls port %v:\n", listen.Addr())
	err = s.Serve(listen)
	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	// Parsing environment variables
	svrCfg, cfgPath, err := util.GetConf()
	if err != nil {
		log.Fatalf("GetConf() failed: %v", err)
	}

	// launch mTLS server
	launchServer(svrCfg, cfgPath)
}
