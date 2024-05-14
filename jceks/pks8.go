package jceks

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// JavaKeyEncryptionOID1 is the object identifier for one type of
	// password-based encryption used in .jceks files.
	JavaKeyEncryptionOID1 = asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1,
	}

	// JavaKeyEncryptionOID2 is the object identifier for one type of
	// password-based encryption used in .jceks files.
	JavaKeyEncryptionOID2 = asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 42, 2, 19, 1,
	}

	// RFC 3279 § 2.3
	oidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// RFC 5480 § 2.1.1
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Java appears to want unused parameters structures encoded as an
	// ASN.1 NULL type.
	asn1NULL = asn1.RawValue{
		FullBytes: []byte{0x05, 0x00},
	}
)

// EncryptedPrivateKeyInfo is the ASN.1 structure used to hold an encrypted
// private key. It is defined in RFC 5208 § 6:
//
//	https://tools.ietf.org/html/rfc5208#section-6
type EncryptedPrivateKeyInfo struct {
	// Algo identifies the encryption algorithm (and any associated
	// parameters) used to encrypt EncryptedData.
	Algo pkix.AlgorithmIdentifier

	// EncryptedData is an encrypted, marshalled PrivateKeyInfo.
	EncryptedData []byte
}

// PrivateKeyInfo is the ASN.1 structure used to hold a private key. It is
// defined in RFC 52080 § 5:
//
//	https://tools.ietf.org/html/rfc5208#section-5
type PrivateKeyInfo struct {
	// Version of structure. Should be zero.
	Version int

	// Algo denotes the private key algorithm (e.g. RSA).
	Algo pkix.AlgorithmIdentifier

	// PrivateKey is the marshalled private key. It should be interpreted
	// according to Algo.
	PrivateKey []byte
}

// DecryptPKCS8 decrypts a PKCS#8 EncryptedPrivateKeyInfo, presumably returning
// a marshalled PrivateKeyInfo structure. It only knows how to handle the two
// encryption algorithms that are used by the Java keytool program.
// DecryptPKCS8 декодирует зашифрованный закрытый ключ PKCS#8 в формате JCEKS.
func DecryptPKCS8(raw []byte, password string) ([]byte, error) {
	// Распарсить ASN.1 структуру и убедиться, что нет лишних данных
	var keyInfo EncryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(raw, &keyInfo)
	if err != nil {
		return nil, errors.New("неверная структура закрытого ключа PKCS#8")
	}
	if len(rest) != 0 {
		return nil, errors.New("лишние данные после закрытого ключа PKCS#8")
	}

	// Проверить, что алгоритм шифрования соответствует JCEKS
	switch {
	case keyInfo.Algo.Algorithm.Equal(JavaKeyEncryptionOID1):
		// Этот алгоритм не имеет параметров
		if len(keyInfo.Algo.Parameters.Bytes) != 0 {
			return nil, errors.New("неожидаемые параметры алгоритма")
		}
		// Расшифровать с использованием кастомного алгоритма JCEKS
		return DecryptJavaKeyEncryption1(keyInfo.EncryptedData, password)

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм шифрования %v",
			keyInfo.Algo.Algorithm)
	}
}

// MarshalPKCS8 маршализует закрытый ключ в структуру PKCS#8 в формате JCEKS.
func MarshalPKCS8(key interface{}) ([]byte, error) {
	var ki PrivateKeyInfo

	switch key := key.(type) {
	case *rsa.PrivateKey:
		// Записываем закрытый ключ в PKCS#1 формат
		ki.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1NULL,
		}
		ki.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	case *ecdsa.PrivateKey:
		// Параметры для алгоритма EC должны содержать информацию о кривой
		c, err := oidFromNamedCurve(key)
		if err != nil {
			return nil, err
		}
		ki.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
		}
		ki.Algo.Parameters.FullBytes, err = asn1.Marshal(c)
		if err != nil {
			return nil, fmt.Errorf("ошибка при маршализации параметров EC: %v", err)
		}

		// Маршализуем закрытый ключ EC
		ki.PrivateKey, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("ошибка при маршализации закрытого ключа EC: %v", err)
		}

	default:
		return nil, fmt.Errorf("неподдерживаемый тип закрытого ключа %T", key)
	}

	// Маршализуем структуру PKCS#8
	raw, err := asn1.Marshal(ki)
	if err != nil {
		return nil, fmt.Errorf("ошибка при маршализации PrivateKeyInfo: %v", err)
	}

	return raw, nil
}

// oidFromNamedCurve returns an OID which identifies the curve used in the
// given key.
func oidFromNamedCurve(key *ecdsa.PrivateKey) (asn1.ObjectIdentifier, error) {
	switch key.Params().Name {
	case "P-224":
		return oidNamedCurveP224, nil
	case "P-256":
		return oidNamedCurveP256, nil
	case "P-384":
		return oidNamedCurveP384, nil
	case "P-521":
		return oidNamedCurveP521, nil
	}
	return nil, fmt.Errorf("unknown named curve %q", key.Params().Name)
}

// DecryptJavaKeyEncryption1 decrypts ciphertext encrypted with one of the Java
// key encryption algorithms.
//
// PLEASE NOTE: this appears to be custom crypto. You should *never* do this. DO
// NOT RE-USE THIS CODE. If you want an example of how to encrypt a blob of data
// or a file with a password, then see the password-encrypt example at:
//
//	https://github.com/lwithers/go-crypto-examples
func DecryptJavaKeyEncryption1(ciphertext []byte, password string,
) ([]byte, error) {
	// split the blob into salt:ciphertext:digest
	if len(ciphertext) <= 40 {
		return nil, errors.New("not enough data for encryption type 1")
	}
	salt := ciphertext[:20]
	digest := ciphertext[len(ciphertext)-20:]
	ciphertext = ciphertext[20 : len(ciphertext)-20]

	// XOR the SHA-1-derived bytestream with the "ciphertext" to recover
	// the plaintext
	passwd := PasswordUTF16(password)
	xorStream := xorStreamForJavaKeyEncryption1(len(ciphertext),
		passwd, salt)
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ xorStream[i]
	}

	// test that the SHA-1 hash over (passwd+plaintext) matches the recorded
	// digest
	md := sha1.New()
	md.Write(passwd)
	md.Write(plaintext)
	computed := md.Sum(nil)
	if !bytes.Equal(computed, digest) {
		return nil, errors.New("invalid password")
	}

	return plaintext, nil
}

// EncryptJavaKeyEncryption1 encrypts plaintext with one of the Java key
// encryption algorithms.
//
// PLEASE NOTE: this appears to be custom crypto. You should *never* do this. DO
// NOT RE-USE THIS CODE. If you want an example of how to encrypt a blob of data
// or a file with a password, then see the password-encrypt example at:
//
//	https://github.com/lwithers/go-crypto-examples
func EncryptJavaKeyEncryption1(plaintext []byte, password string,
) ([]byte, error) {
	// generate a salt
	var salt [20]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	// XOR the SHA-1-derived bytestream with the plaintext to derive the
	// "ciphertext"
	passwd := PasswordUTF16(password)
	xorStream := xorStreamForJavaKeyEncryption1(len(plaintext),
		passwd, salt[:])
	ciphertext := make([]byte, len(plaintext))
	for i := range ciphertext {
		ciphertext[i] = plaintext[i] ^ xorStream[i]
	}

	// compute the SHA-1 hash over (passwd+plaintext)
	md := sha1.New()
	md.Write(passwd)
	md.Write(plaintext)
	digest := md.Sum(nil)

	// return salt:ciphertext:digest
	result := make([]byte, 0, len(salt)+len(ciphertext)+len(digest))
	result = append(result, salt[:]...)
	result = append(result, ciphertext...)
	result = append(result, digest...)
	return result, nil
}

// xorStreamForJavaKeyEncryption1 returns a stream of bytes that is XORed with
// the plaintext to produce the ciphertext.  We iteratively use a SHA-1 hash
// over (passwd+lastHash) to produce a stream of bytes we then XOR with the
// "ciphertext". For the first block we use ‘salt’ in place of ‘last_hash’.
//
// PLEASE NOTE: this appears to be custom crypto. You should *never* do this. DO
// NOT RE-USE THIS CODE. If you want an example of how to encrypt a blob of data
// or a file with a password, then see the password-encrypt example at:
//
//	https://github.com/lwithers/go-crypto-examples
func xorStreamForJavaKeyEncryption1(strlen int, passwd, salt []byte) []byte {
	xorStream := make([]byte, strlen)
	wrXor := xorStream
	lastHash := make([]byte, 20)
	copy(lastHash, salt)

	for len(wrXor) > 0 {
		md := sha1.New()
		md.Write(passwd)
		md.Write(lastHash)
		lastHash = md.Sum(lastHash[:0])

		copy(wrXor, lastHash)
		if len(wrXor) <= 20 {
			break
		}
		wrXor = wrXor[20:]
	}
	return xorStream
}
