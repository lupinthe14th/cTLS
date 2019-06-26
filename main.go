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

func statePeerCertificateExpireDate(host string, port uint32) (expireTime time.Time, err error) {
	conn, err := tls.Dial("tcp", fmt.Sprint(host, ":", port), &tls.Config{})
	if err != nil {
		log.Errorf("client: dial: %s", err)
		return expireTime, err
	}
	defer conn.Close()
	log.Debugln("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		if !v.IsCA {
			log.Println(v.Subject)
			expireTime = v.NotAfter
			log.Println("peer certificates: expire time: ", expireTime)
		}
	}
	log.Debugln("client: exiting")
	return expireTime, nil
}

func main() {
	expireTime, err := statePeerCertificateExpireDate("www.google.com", 443)
	if err != nil {
		log.Panicln(err)
	}
	expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
	fmt.Println("Peer Certificates: expire time: ", expireJSTTime)
}
