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

func statePeerCertificateExpireDate(host, port string) (expireTime time.Time, err error) {
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
