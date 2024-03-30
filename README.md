# Authenticate API
1) First we need to make two keys for the JWT token

    While in the root folder, write commands:
```bash
mkdir certs
```
```bash
cd certs
```
```bash
# Generate an RSA private key, of size 2048
openssl genrsa -out jwt-private.pem 2048
```
```bash
# Extract the public key from the key pair, which can be used in a certificate
openssl rsa -in jwt-private.pem -outform PEM -pubout -out jwt-public.pem
```
Don't forget to add the certs folder to gitignore!