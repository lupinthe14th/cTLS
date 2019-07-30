package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/infobloxopen/atlas-app-toolkit/gorm/resource"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/tcvem/backend/cmd/client"
	"github.com/tcvem/backend/pkg/pb"
)

func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AddConfigPath(viper.GetString("config.source"))
	if viper.GetString("config.file") != "" {
		log.Printf("Serving from configuration file: %s", viper.GetString("config.file"))
		viper.SetConfigName(viper.GetString("config.file"))
		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("cannot load configuration: %v", err)
		}
	} else {
		log.Printf("Serving from default values, environment variables, and/or flags")
	}
	resource.RegisterApplication(viper.GetString("app.id"))
	resource.SetPlural()
}

func startTLSConnectionState(host, port string) (state tls.ConnectionState, err error) {
	addr := fmt.Sprint(host, ":", port)
	// Dial the tcp connection
	_, err = net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Errorf("net dial: %s", err)
		return state, err
	}
	// Dial the SMTP server
	conn, err := smtp.Dial(addr)
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
	addr := fmt.Sprint(host, ":", port)
	// Dial the tcp connection
	_, err = net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Errorf("net dial: %s", err)
		return state, err
	}

	// Dial the tls connection
	conn, err := tls.Dial("tcp", addr, &tls.Config{})
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
			return expireTime, err
		}
		log.Debugf("startTLS connection state: %v", state)
	default:
		log.Debugf("case: %v", port)
		state, err = tlsConnectionState(host, port)
		if err != nil {
			log.Errorf("TLS connection state: %s", err)
			return expireTime, err
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

func checkStatePeerCertificateExpireDate(addrs *pb.ListCertficateResponse) error {
	var wg sync.WaitGroup
	for i, a := range addrs.Results {
		wg.Add(1)
		go func(i int, a *pb.Certficate) {
			defer wg.Done()
			expireTime, err := statePeerCertificateExpireDate(a.Host, a.Port)
			if err != nil {
				log.Error(err)
			}
			expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
			fmt.Println(i, ": Peer Certificates: expire time:", expireJSTTime)
		}(i, a)
	}
	wg.Wait()
	return nil
}

func main() {
	// Set up a connection to the server.
	address := fmt.Sprintf("%s:%s", viper.GetString("server.address"), viper.GetString("server.port"))

	cc, err := client.NewTcvemClient(address)
	if err != nil {
		log.Panic(err)
	}

	addrs, err := cc.GetListCertficate()
	if err != nil {
		log.Panic(err)
	}
	checkStatePeerCertificateExpireDate(addrs)
}
