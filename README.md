Sidra Api - RSA Signature Validator Plugin
# RSA Signature Validator Plugin

## Description

The RSA Signature Validator Plugin is a security plugin for verifying RSA-based signatures included in requests. It supports two types of RSA signature schemes:
- **PKCS#1 v1.5 (Signature-Type: PKCS)**
- **PSS (Probabilistic Signature Scheme) (Signature-Type: PSS)**

The plugin ensures that incoming requests contain valid digital signatures to verify authenticity and integrity.

## How It Works

1. The Public Key (PEM format) is retrieved from the environment variable `PUBLIC_PEM_SALESFORCE`.
2. The plugin expects the following headers in each request:
    - `signature`: Base64-encoded RSA signature.
    - `signature-type`: Signature scheme, either `PKCS` or `PSS`.
3. The plugin verifies the RSA signature using the selected scheme against the request body.

### Responses:
- **200 OK**: Signature is valid.
- **400 Bad Request**: Missing or invalid headers.
- **401 Unauthorized**: Signature verification failed.
- **502 Bad Gateway**: Error parsing the public key.

## Prerequisites

- Golang must be installed.
- Sidra Api and Sidra Plugins Hub are properly configured.
- A valid RSA public key in PEM format is required.

## Environment Variables

| Variable               | Description                     | Example                                |
|------------------------|---------------------------------|----------------------------------------|
| `PUBLIC_PEM_SALESFORCE`| RSA public key in PEM format    | `"-----BEGIN PUBLIC KEY-----\n..."`    |

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/sidra-api/plugin-rsa.git
    cd plugin-rsa
    ```
2. Set the Environment Variable: Add the RSA public key to the environment variable:
    ```sh
    export PUBLIC_PEM_SALESFORCE="-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_HERE\n-----END PUBLIC KEY-----"
    ```
3. Build and Run the Plugin:
    ```sh
    go build -o rsa-validator
    ./rsa-validator
    ```

## Testing the Plugin

Use Postman or curl to test the plugin.

### Example Request
1. Generate an RSA signature for your payload using a private key.
2. Base64 encode the signature.
3. Send a request with the following headers:
    ```sh
    curl -X POST http://localhost:8080 \
      -H "signature: BASE64_SIGNATURE" \
      -H "signature-type: PKCS" \
      -d "Your payload data"
    ```

### Expected Responses

| Status Code          | Description                       | Response Body                                      |
|----------------------|-----------------------------------|----------------------------------------------------|
| **200 OK**           | Signature is valid                | Signature valid                                    |
| **400 Bad Request**  | Missing or invalid headers        | Missing signature header or Invalid signature-type. Use 'PKCS' or 'PSS' |
| **401 Unauthorized** | Signature verification failed     | Invalid signature                                  |
| **502 Bad Gateway**  | Error parsing public key          | Failed to parse public key                         |

## Supported Signature Schemes

- **PKCS#1 v1.5**: Traditional RSA signature scheme.
- **PSS**: A modern, probabilistic signature scheme.

To specify the scheme, include `signature-type` in the request headers as either `PKCS` or `PSS`.

## Notes

- Ensure the public key is properly formatted in PEM.
- The payload used to generate the signature must match the request body.

## License

This project is licensed under the MIT License.