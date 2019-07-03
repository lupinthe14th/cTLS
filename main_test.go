package main

import (
	"testing"
	"time"
)

func TestStatePeerCertificateExpireDate(t *testing.T) {
	var tests = []struct {
		host string
		port string
	}{
		{host: "www.google.com", port: "443"},
		{host: "smtp.gmail.com", port: "587"},
	}

	for _, tt := range tests {
		expireTime, err := statePeerCertificateExpireDate(tt.host, tt.port)
		if err != nil {
			t.Error(err)
		}
		expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
		t.Logf("Peer Certificates: expire time: %+v", expireJSTTime)
	}
}
