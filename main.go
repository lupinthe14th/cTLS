package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
}

func main() {
	conn, err := tls.Dial("tcp", "www.google.com:443", &tls.Config{})
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		if !v.IsCA {
			log.Println(v.Subject)
			expireUTCTime := v.NotAfter
			expireJSTTime := expireUTCTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
			fmt.Println("Peer Certificates: expire date: ", expireJSTTime)
		}
	}
	log.Print("client: exiting")
}
