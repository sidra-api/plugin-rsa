package main

import (
	"net/http"
	"os"
	"encoding/json"

	"github.com/sidra-gateway/go-pdk/server"
	"github.com/lukluk/pkcs-validator/lib" //Library untuk RSA validation
)

func rsaValidator(req server.Request) server.Response{
	// Ambil header signature dari request
	signature := req.Headers["signature"]
	if signature == "" {
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Signature header is missing",
		}
	}

	// Muat public key dari environment
	pubKeyPEM := os.Getenv("PUBLIC_PEM_SALESFORCE")
	if pubKeyPEM == "" {
		return server.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "Public key is not configured.",
		}
	}

	// Parse public key
	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(pubKeyPEM)
	if err != nil {
		return server.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "Invalid public key: " + err.Error(),
		}
	}

	// Ambil payload dari body request
	var payload string
	if err := json.Unmarshal([]byte(req.Body), &payload); err != nil || len(payload) == 0 {
		return server.Response{
			StatusCode: http.StatusBadRequest,
			Body:       "Invalid payload",
		}
	}

	// Verifikasi tanda tangan menggunakan library PKCS
	signer := lib.SignatureTypePKCS{}
	err = signer.Verify(pubKey, string(payload), signature)
	if err != nil {
		return server.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       "Invalid signature: " + err.Error(),
		}
	}

	// Jika valid, lanjutkan ke tahap berikutnya
	return server.Response{
		StatusCode: http.StatusOK,
		Body:       "Signature verified successfully.",
	}
}

func main() {
	//Daftarkan plugin dgn nama & fungsi handler
	server.NewServer("rsa-validator", rsaValidator).Start()
}