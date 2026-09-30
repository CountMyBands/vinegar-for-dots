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

// certsMarker precedes every certificate added to Studio's bundle, which
// are always appended after Studio's own certificates.
const certsMarker = "\n# Added by Vinegar from "

// addStudioCerts adds the certificates from the configured CA certificates
// file to Studio's bundled CA certificates, which Studio uses exclusively for
// its own HTTPS requests. Without this, Studio rejects connections made
// through a TLS-intercepting proxy (such as one used by a VM) even when the
// system trusts the proxy's CA.
//
// This is opt-in and scoped to the configured file: certificates previously
// added by Vinegar are always removed first, restoring Studio's own bundle
// when no file is configured. Studio re-extracts its bundle on every update.
func (b *bootstrapper) addStudioCerts() error {
	bundle := filepath.Join(b.dir, "ssl", "cacert.pem")
	data, err := os.ReadFile(bundle)
	if errors.Is(err, os.ErrNotExist) {
		if b.cfg.Studio.CACerts != "" {
			slog.Warn("Studio CA bundle missing, not adding certificates")
		}
		return nil
	} else if err != nil {
		return err
	}

	studio := data
	if i := bytes.Index(data, []byte(certsMarker)); i >= 0 {
		studio = data[:i]
	}

	name := b.cfg.Studio.CACerts
	if name == "" {
		if len(studio) != len(data) {
			slog.Info("Restoring Studio CA bundle", "bundle", bundle)
			return os.WriteFile(bundle, studio, 0o644)
		}
		return nil
	}

	extra, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("ca certificates: %w", err)
	}
	certs := pemCerts(extra)
	if len(certs) == 0 {
		return fmt.Errorf("ca certificates: no certificates in %s", name)
	}

	have := make(map[[sha256.Size]byte]bool)
	for _, c := range pemCerts(studio) {
		have[sha256.Sum256(c.Raw)] = true
	}

	out := bytes.NewBuffer(bytes.Clone(studio))
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		if have[sum] {
			continue
		}
		have[sum] = true

		slog.Info("Adding CA certificate to Studio",
			"subject", c.Subject.String(), "sha256", fmt.Sprintf("%x", sum))
		fmt.Fprintf(out, "%s%s\n# %s\n", certsMarker, name, c.Subject)
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	if bytes.Equal(out.Bytes(), data) {
		return nil
	}

	b.message(L("Adding CA Certificates"), "bundle", bundle, "from", name)
	return os.WriteFile(bundle, out.Bytes(), 0o644)
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
