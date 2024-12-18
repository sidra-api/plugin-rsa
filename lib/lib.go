package lib

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
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
		log.Printf("ERROR: Failed to decode signature: %v\n", err)
		return errors.New("failed to decode signature")
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], bSignature)
	if err != nil {
		log.Printf("ERROR: PKCS signature verification failed: %v\n", err)
		return errors.New("signature verification failed")
	}

	log.Println("INFO: PKCS signature verification successful")
	return nil
}

// PSS (Probabilistic Signature Scheme) implementation
type SignatureTypePSS struct{}

func (s *SignatureTypePSS) Verify(pubKey *rsa.PublicKey, msg string, base64Signature string) error {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		log.Printf("ERROR: Failed to decode signature: %v\n", err)
		return errors.New("failed to decode signature")
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], bSignature, nil)
	if err != nil {
		log.Printf("ERROR: PSS signature verification failed: %v\n", err)
		return errors.New("signature verification failed")
	}

	log.Println("INFO: PSS signature verification successful")
	return nil
}

// Fungsi untuk mem-parsing public key dari string PEM
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		log.Println("ERROR: Failed to parse PEM block containing the key")
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("ERROR: Failed to parse public key: %v\n", err)
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		log.Println("INFO: Public key successfully parsed")
		return pub, nil
	default:
		log.Println("ERROR: Key type is not RSA")
		return nil, errors.New("key type is not RSA")
	}
}
