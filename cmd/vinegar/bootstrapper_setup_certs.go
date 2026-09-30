package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/pojntfx/go-gettext/pkg/i18n"
)

// systemCertFiles are the locations of the system CA bundle, in the
// same order that Go's crypto/x509 checks them.
var systemCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
	"/usr/local/share/certs/ca-root-nss.crt",            // FreeBSD
}

// systemCerts returns the path and contents of the system CA bundle.
func systemCerts() (string, []byte, error) {
	files := systemCertFiles
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		files = []string{f}
	}

	for _, f := range files {
		b, err := os.ReadFile(f)
		if err == nil {
			return f, b, nil
		}
	}
	return "", nil, errors.New("system CA bundle not found")
}

// trustSystemCerts appends the certificates trusted by the system to
// Studio's bundled CA certificates, which Studio uses exclusively for
// its own HTTPS requests. Without this, Studio rejects connections made
// through a TLS-intercepting proxy (such as one used by a VM) that the
// system otherwise trusts. Only certificates missing from Studio's
// bundle are added, and Studio re-extracts its bundle on every update.
func (b *bootstrapper) trustSystemCerts() error {
	bundle := filepath.Join(b.dir, "ssl", "cacert.pem")
	studio, err := os.ReadFile(bundle)
	if errors.Is(err, os.ErrNotExist) {
		slog.Warn("Studio CA bundle missing, not adding system certificates")
		return nil
	} else if err != nil {
		return err
	}

	name, system, err := systemCerts()
	if err != nil {
		slog.Warn("Not adding system certificates to Studio", "err", err)
		return nil
	}

	have := make(map[[sha256.Size]byte]bool)
	for _, c := range pemCerts(studio) {
		have[sha256.Sum256(c.Raw)] = true
	}

	var add bytes.Buffer
	for _, c := range pemCerts(system) {
		sum := sha256.Sum256(c.Raw)
		if have[sum] {
			continue
		}
		have[sum] = true

		slog.Info("Adding system certificate to Studio",
			"subject", c.Subject.String(), "sha256", fmt.Sprintf("%x", sum))
		fmt.Fprintf(&add, "\n# Added by Vinegar from %s\n# %s\n", name, c.Subject)
		if err := pem.Encode(&add, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	if add.Len() == 0 {
		return nil
	}

	b.message(L("Adding System Certificates"), "bundle", bundle, "from", name)

	f, err := os.OpenFile(bundle, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = add.WriteTo(f)
	return err
}

// pemCerts returns all valid certificates in the given PEM data.
func pemCerts(data []byte) (certs []*x509.Certificate) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}
	return
}
