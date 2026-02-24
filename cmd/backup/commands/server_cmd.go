package commands

import (
	"backup/internal/cli"
	"backup/internal/s3server"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("server", serverArgs{}, runServer)
}

type serverArgs struct {
	Listen string `arg:"--listen" default:":0"`
	Dir    string `arg:"--dir"`
	Cert   string `arg:"--cert"`
	Key    string `arg:"--key"`
	Region string `arg:"--region" default:"us-east-1"`
}

func (serverArgs) Description() string {
	return "\nstart local s3 server\n"
}

func runServer() {
	var args serverArgs
	arg.MustParse(&args)
	if args.Dir == "" {
		args.Dir = "."
	}
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" || secretKey == "" {
		panic("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}
	certPath := args.Cert
	keyPath := args.Key
	if certPath == "" || keyPath == "" {
		certDir := filepath.Join(args.Dir, ".backup-server-tls")
		var err error
		certPath, keyPath, err = s3server.GenerateSelfSignedCert(certDir)
		if err != nil {
			panic(err)
		}
	}

	listener, err := net.Listen("tcp", args.Listen)
	if err != nil {
		panic(err)
	}
	defer func() { _ = listener.Close() }()
	server := &s3server.Server{
		Dir:       args.Dir,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    args.Region,
	}
	httpServer := &http.Server{
		Handler:   server,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	fmt.Println(listener.Addr().String())
	if err := httpServer.ServeTLS(listener, certPath, keyPath); err != nil {
		panic(err)
	}
}
