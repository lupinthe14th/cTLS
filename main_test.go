package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatePeerCertificateExpireDate(t *testing.T) {
	var tests = []struct {
		name string
		host string
		port string
		err  bool
	}{
		{name: "No Error", host: "www.google.com", port: "443", err: false},
		{name: "No Error", host: "smtp.gmail.com", port: "587", err: false},
		{name: "Error", host: "www.google.com", port: "80", err: true},
		{name: "Error", host: "smtp.gmail.com", port: "25", err: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := statePeerCertificateExpireDate(tt.host, tt.port)
			if !tt.err {
				assert.NoError(t, err)
			}
			if tt.err {
				assert.Error(t, err)
			}
		})
	}
}
