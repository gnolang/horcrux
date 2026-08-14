package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
)

// ErrClusterPeerNotAllowed is returned during the TLS handshake when a peer
// presents a connection identity that is not in the configured allowlist.
var ErrClusterPeerNotAllowed = errors.New("cluster peer public key not in allowlist")

// ClusterTLSConfig returns the mutual-TLS config for the cosigner cluster
// transport, or (nil, nil) when clusterKeyFile is not configured (insecure
// transport, the historical default). The same config is used for both the
// cluster gRPC server and the client dials to peers.
func ClusterTLSConfig(cfg *RuntimeConfig) (*tls.Config, error) {
	keyFile := cfg.ClusterKeyFilePath()
	if keyFile == "" {
		return nil, nil
	}

	identity, err := LoadConnKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster key: %w", err)
	}

	allowed, err := cfg.Config.ThresholdModeConfig.ClusterPeerPubKeys()
	if err != nil {
		return nil, err
	}

	return clusterTLSConfig(identity, allowed)
}

// clusterTLSConfig builds a mutual-TLS config for the cosigner cluster transport.
//
// identity is this cosigner's ed25519 key; it is presented as a self-signed
// certificate (no CA). allowed is the set of peer ed25519 public keys permitted
// to connect. Both ends pin the peer's certificate public key against allowed,
// so authentication does not depend on a certificate authority or hostnames.
func clusterTLSConfig(identity cometcryptoed25519.PrivKey, allowed []cometcryptoed25519.PubKey) (*tls.Config, error) {
	cert, err := selfSignedCert(identity)
	if err != nil {
		return nil, err
	}

	verify := pinnedPeerVerifier(allowed)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// We authenticate peers by pinning their certificate public key against
		// the allowlist, not via a CA, so the default chain/hostname verification
		// is disabled and fully replaced by VerifyPeerCertificate (which TLS still
		// invokes when InsecureSkipVerify is set). RequireAnyClientCert makes the
		// server demand a client certificate so the same pinning runs both ways.
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true, //nolint:gosec // peer identity is pinned in VerifyPeerCertificate
		// Disable session resumption so every connection is a full handshake that
		// re-runs VerifyPeerCertificate against the current allowlist. Otherwise a
		// resumed session would skip peer verification, and a cosigner removed from
		// the allowlist could keep connecting until tickets rotated.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verify,
	}, nil
}

// pinnedPeerVerifier returns a VerifyPeerCertificate that accepts a peer only if
// the leaf certificate's ed25519 public key is in allowed.
func pinnedPeerVerifier(allowed []cometcryptoed25519.PubKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrClusterPeerNotAllowed
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		peer, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer certificate is not ed25519: %T", cert.PublicKey)
		}
		for _, a := range allowed {
			// a is a 32-byte ed25519 public key; compare against the presented key.
			if ed25519.PublicKey(a).Equal(peer) {
				return nil
			}
		}
		return ErrClusterPeerNotAllowed
	}
}

// selfSignedCert builds an in-memory self-signed certificate for the ed25519
// identity key. The certificate carries no meaningful subject or SANs because
// peers are authenticated by pinned public key, not by name.
func selfSignedCert(identity cometcryptoed25519.PrivKey) (tls.Certificate, error) {
	priv := ed25519.PrivateKey(identity)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("identity key is not ed25519")
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "horcrux-cosigner"},
		// Validity is not enforced (peers are pinned by public key, and the TLS
		// stack's period check is part of the disabled default verification), but
		// x509 caps NotAfter at year 9999, so use a wide in-range window.
		NotBefore:   time.Unix(0, 0),
		NotAfter:    time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        template,
	}, nil
}
