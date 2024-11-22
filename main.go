package main

import (
	"net/http"
	"os"
	//"encoding/json"

	"github.com/sidra-gateway/go-pdk/server"
	"github.com/sidra-gateway/plugin-rsa/lib" //Library untuk RSA validation
)

func main() {
	rsaValidator := server.NewServer("rsa-validator", handleRequest)
	if err := rsaValidator.Start(); err != nil {
		panic(err)
	}
}

func handleRequest(req server.Request) server.Response {
	signature := req.Headers["signature"]
	signatureType := req.Headers["signature-type"] // PKCS or PSS
	if signature == "" {
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing signature header",
		}
	}

	if signatureType == "" {
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Missing signature-type header",
		}
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(os.Getenv("PUBLIC_PEM_SALESFORCE"))
	if err != nil {
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
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid signature-type. Use 'PKCS' or 'PSS'",
		}
	}

	// Verifikasi tanda tangan
	err = verifier.Verify(pubKey, payload, signature)
	if err != nil {
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid signature",
		}
	}

	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "Signature valid",
	}
}