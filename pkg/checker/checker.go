package checker

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tcvem/backend/pkg/pb"
)

func startTLSConnectionState(logger *logrus.Logger, host, port string) (state tls.ConnectionState, err error) {
	addr := fmt.Sprint(host, ":", port)
	// Dial the tcp connection
	_, err = net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logger.Errorf("net dial: %s", err)
		return state, err
	}
	// Dial the SMTP server
	conn, err := smtp.Dial(addr)
	if err != nil {
		logger.Errorf("smtp: dial: %s", err)
		return state, err
	}
	defer conn.Close()
	conn.StartTLS(&tls.Config{ServerName: host})
	state, _ = conn.TLSConnectionState()
	return state, nil
}

func tlsConnectionState(logger *logrus.Logger, host, port string) (state tls.ConnectionState, err error) {
	addr := fmt.Sprint(host, ":", port)
	// Dial the tcp connection
	_, err = net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		logger.Errorf("net dial: %s", err)
		return state, err
	}

	// Dial the tls connection
	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		logger.Errorf("tls: dial: %s", err)
		return state, err
	}
	defer conn.Close()
	logger.Debugln("client: connected to: ", conn.RemoteAddr())

	state = conn.ConnectionState()
	return state, nil
}

func statePeerCertificateExpireDate(logger *logrus.Logger, host, port string) (expireTime time.Time, err error) {
	var state tls.ConnectionState
	switch port {
	case "587":
		logger.Debugf("case: %v", port)
		state, err = startTLSConnectionState(logger, host, port)
		if err != nil {
			logger.Errorf("startTLS connection state: %s", err)
			return expireTime, err
		}
		logger.Debugf("startTLS connection state: %v", state)
	default:
		logger.Debugf("case: %v", port)
		state, err = tlsConnectionState(logger, host, port)
		if err != nil {
			logger.Errorf("TLS connection state: %s", err)
			return expireTime, err
		}
		logger.Debugf("TLS connection state: %v", state)
	}

	for _, v := range state.PeerCertificates {
		if !v.IsCA {
			logger.Println(v.Subject)
			expireTime = v.NotAfter
			logger.Println("peer certificates: expire time: ", expireTime)
		}
	}
	logger.Debugln("client: exiting")
	return expireTime, nil
}

func CheckStatePeerCertificateExpireDate(logger *logrus.Logger, addrs *pb.ListCertficateResponse) error {
	var wg sync.WaitGroup
	for i, a := range addrs.Results {
		wg.Add(1)
		go func(i int, a *pb.Certficate) {
			defer wg.Done()
			expireTime, err := statePeerCertificateExpireDate(logger, a.Host, a.Port)
			if err != nil {
				logger.Error(err)
			}
			expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
			fmt.Println(i, ": Peer Certificates: expire time:", expireJSTTime)
		}(i, a)
	}
	wg.Wait()
	return nil
}
