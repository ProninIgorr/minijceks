package jceks

import (
	"crypto/sha256"
	"crypto/x509"
	"time"
	"unicode/utf16"
)

const (
	jceksMagic      = 0xcececece
	jceksVersion    = 0x02
	DigestSeparator = "Mighty Aphrodite"
	CertType        = "X.509"
)

// Keystore represents a single JKS file. It holds a list of certificates and a
// list of keypairs (private keys with associated certificate chains).
type Keystore struct {
	// Certs is a list of CA certificates to trust. It may contain either
	// root or intermediate CA certificates. It should not contain end-user
	// certificates.
	Certs []*Cert

	// Keypairs is a list of private keys. Each key may have a certificate
	// chain associated with it.
	Keypairs []*Keypair
}

// Options for manipulating a keystore. These allow the caller to specify the
// password(s) used, or to skip the digest verification if the password is
// unknown.
type Options struct {
	// Password is used as part of a SHA-1 digest over the .jks file.
	Password string

	// SkipVerifyDigest can be set to skip digest verification when loading
	// a keystore file. This will inhibit errors from Parse if you don't
	// know the password.
	SkipVerifyDigest bool

	// KeyPasswords are used to generate the "encryption" keys for stored
	// private keys. The map's key is the alias of the private key, and the
	// value is the password. If there is no entry in the map for a given
	// alias, then the top-level Password is inherited. Empty strings are
	// interpreted as an empty password, so use delete() if you truly want
	// to delete values.
	KeyPasswords map[string]string
}

// Cert holds a certificate to trust.
type Cert struct {
	// Alias is a name used to refer to this certificate.
	Alias string

	// Timestamp records when this record was created.
	Timestamp time.Time

	// Raw is the raw X.509 certificate marshalled in DER form.
	Raw []byte

	// CertErr is set if there is an error parsing the certificate.
	CertErr error

	// Cert is the parsed X.509 certificate.
	Cert *x509.Certificate
}

// Keypair holds a private key and an associated certificate chain.
type Keypair struct {
	// Alias is a name used to refer to this keypair.
	Alias string

	// Timestamp records when this record was created.
	Timestamp time.Time

	// PrivKeyErr is set if an error is encountered during decryption or
	// unmarshalling of the decrypted key.
	PrivKeyErr error

	// EncryptedKey is the raw PKCS#8 marshalled EncryptedPrivateKeyInfo.
	EncryptedKey []byte

	// RawKey is the raw PKCS#8 marshalled PrivateKeyInfo, after it has
	// been decrypted. It will not have been set if decryption failed.
	RawKey []byte

	// PrivateKey is the unmarshalled private key. It will not have been
	// set if decryption failed or if unmarshalling failed.
	PrivateKey interface{}

	// CertChain is a chain of certificates associated with the private key.
	// The first entry in the chain (index 0) should correspond to
	// PrivateKey; there should then follow any intermediate CAs. In
	// general the root CA should not be part of the chain.
	CertChain []*KeypairCert
}

// KeypairCert is an entry in the certificate chain associated with a Keypair.
type KeypairCert struct {
	// Raw X.509 certificate data (in DER form).
	Raw []byte

	// Cert is the parsed X.509 certificate. It is nil if the certificate
	// could not be parsed.
	Cert *x509.Certificate

	// CertErr records any error encountered while parsing a certificate.
	CertErr error
}

var defaultOptions = Options{
	SkipVerifyDigest: true,
}

// ComputeDigest performs a SHA-256 hash over the given file data.
func ComputeDigest(raw []byte, passwd string) []byte {
	// compute SHA-256 digest over the construct:
	//  UTF-16(password) + UTF-8(DigestSeparator) + raw
	md := sha256.New()
	p := PasswordUTF16(passwd)
	md.Write(p)
	md.Write([]byte(DigestSeparator))
	md.Write(raw)
	return md.Sum(nil)
}

// PasswordUTF16 remains unchanged as it correctly implements UTF-16 encoding.
func PasswordUTF16(passwd string) []byte {
	var u []byte
	for _, r := range passwd {
		if r < 0x10000 {
			u = append(u, byte((r>>8)&0xFF))
			u = append(u, byte(r&0xFF))
		} else {
			r1, r2 := utf16.EncodeRune(r)
			u = append(u, byte((r1>>8)&0xFF))
			u = append(u, byte(r1&0xFF))
			u = append(u, byte((r2>>8)&0xFF))
			u = append(u, byte(r2&0xFF))
		}
	}
	return u
}

// Additional functions to parse, load, and save JCEKS keystore would be implemented here.
// This includes handling secret keys, using appropriate cryptographic algorithms for JCEKS,
// and ensuring compatibility with the JCEKS format specifications.
