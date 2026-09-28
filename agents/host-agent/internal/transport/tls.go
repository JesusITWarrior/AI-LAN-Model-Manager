package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func ClientTLSConfig(cert tls.Certificate, caPEM []byte, serverName string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) || len(cert.Certificate) == 0 || serverName == "" {
		return nil, errors.New("transport tls configuration invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName}, nil
}
func ServerTLSConfig(cert tls.Certificate, caPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) || len(cert.Certificate) == 0 {
		return nil, errors.New("transport tls configuration invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
