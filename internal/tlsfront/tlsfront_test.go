package tlsfront

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An RSA-key-exchange-only TLS 1.2 client (what the PS3 firmware offers)
// gets an exact leaf for its SNI that chains to the CA.
func TestRSAKeyExchangeLeafPerSNI(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test PS3 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	dir := t.TempDir()
	cert, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	front, err := Load(cert, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, host := range []string{"auth.np.ac.playstation.net", "IV0001-NPXS01001-00.auth.np.ac.playstation.net"} {
		server, client := net.Pipe()
		go tls.Server(server, front.Config()).Handshake()
		c := tls.Client(client, &tls.Config{ServerName: host, RootCAs: roots, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}})
		if err := c.Handshake(); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got := c.ConnectionState().CipherSuite; got != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
			t.Fatalf("%s: suite %x", host, got)
		}
		if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != host {
			t.Fatalf("leaf CN %q, want the SNI as sent %q", cn, host)
		}
		c.Close()
	}
	// The same front behind http.Server (what np-account runs) answers a request.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := front.Serve(&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Host)) })})
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}}}
	req, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/", nil)
	req.Host = "native-ps3.np.ac.playstation.net"
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = req.Host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != req.Host {
		t.Fatalf("body %q", body)
	}
}
