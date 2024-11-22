package lib

import (
	"crypto"
	//"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// Interface untuk verifikasi tanda tangan
type SignatureVerifier interface {
	Verify(pubKey *rsa.PublicKey, msg string, signature string) error
}

// PKCS#1 v1.5 implementation
type SignatureTypePKCS struct{}

func (s *SignatureTypePKCS) Verify(pubKey *rsa.PublicKey, msg string, base64Signature string) error {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return errors.New("failed to decode signature")
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], bSignature)
	if err != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

// PSS (Probabilistic Signature Scheme) implementation
type SignatureTypePSS struct{}

func (s *SignatureTypePSS) Verify(pubKey *rsa.PublicKey, msg string, base64Signature string) error {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		return errors.New("failed to decode signature")
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], bSignature, nil)
	if err != nil {
		return errors.New("signature verification failed")
	}

	return nil
}

// Fungsi untuk mem-parsing public key dari string PEM
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}
