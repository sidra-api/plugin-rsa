package main

import (
	"log"
	"net/http"
	"os"

	"github.com/sidra-gateway/go-pdk/server"
	"github.com/sidra-gateway/plugin-rsa/lib" //Library untuk RSA validation
)

func main() {
	log.Println("INFO: Starting RSA Validator Plugin...")
	rsaValidator := server.NewServer("rsa-validator", handleRequest)
	if err := rsaValidator.Start(); err != nil {
		log.Fatalf("ERROR: Failed to start server: %v\n", err)
	}
}

func handleRequest(req server.Request) server.Response {
	signature := req.Headers["signature"]
	signatureType := req.Headers["signature-type"] // PKCS or PSS
	if signature == "" {
		log.Println("WARNING: Missing signature header")
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing signature header",
		}
	}

	if signatureType == "" {
		log.Println("WARNING: Missing signature-type header")
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing signature-type header",
		}
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(os.Getenv("PUBLIC_PEM_SALESFORCE"))
	if err != nil {
		log.Printf("ERROR: Failed to parse public key: %v\n", err)
		return server.Response{
			StatusCode: http.StatusBadGateway,
			Body:       "Failed to parse public key",
		}
	}

	payload := req.Body
	var verifier lib.SignatureVerifier

	// Pilih tipe tanda tangan
	switch signatureType {
	case "PKCS":
		verifier = &lib.SignatureTypePKCS{}
	case "PSS":
		verifier = &lib.SignatureTypePSS{}
	default:
		log.Printf("WARNING: Invalid signature-type: %s\n", signatureType)
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid signature-type. Use 'PKCS' or 'PSS'",
		}
	}

	// Verifikasi tanda tangan
	err = verifier.Verify(pubKey, payload, signature)
	if err != nil {
		log.Printf("WARNING: Invalid signature: %v\n", err)
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid signature",
		}
	}

	log.Printf("INFO: Signature valid for payload: %s\n", payload)
	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "Signature valid",
	}
}