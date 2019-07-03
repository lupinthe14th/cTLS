package main

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
}

func startTLSConnectionState(host, port string) (state tls.ConnectionState, err error) {
	conn, err := smtp.Dial(fmt.Sprint(host, ":", port))
	if err != nil {
		log.Errorf("smtp: dial: %s", err)
		return state, err
	}
	defer conn.Close()
	conn.StartTLS(&tls.Config{ServerName: host})
	state, _ = conn.TLSConnectionState()
	return state, nil
}

func tlsConnectionState(host, port string) (state tls.ConnectionState, err error) {
	conn, err := tls.Dial("tcp", fmt.Sprint(host, ":", port), &tls.Config{})
	if err != nil {
		log.Errorf("tls: dial: %s", err)
		return state, err
	}
	defer conn.Close()
	log.Debugln("client: connected to: ", conn.RemoteAddr())

	state = conn.ConnectionState()
	return state, nil
}

func statePeerCertificateExpireDate(host, port string) (expireTime time.Time, err error) {
	var state tls.ConnectionState
	switch port {
	case "587":
		log.Debugf("case: %v", port)
		state, err = startTLSConnectionState(host, port)
		if err != nil {
			log.Errorf("startTLS connection state: %s", err)
		}
		log.Debugf("startTLS connection state: %v", state)
	default:
		log.Debugf("case: %v", port)
		state, err = tlsConnectionState(host, port)
		if err != nil {
			log.Errorf("TLS connection state: %s", err)
		}
		log.Debugf("TLS connection state: %v", state)
	}

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
	type addr struct {
		host string
		port string
	}
	var addrs = []addr{
		{host: "www.google.com", port: "443"},
		{host: "smtp.gmail.com", port: "587"},
	}

	for _, addr := range addrs {
		expireTime, err := statePeerCertificateExpireDate(addr.host, addr.port)
		if err != nil {
			log.Panicln(err)
		}
		expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
		fmt.Println("Peer Certificates: expire time: ", expireJSTTime)
	}
}
