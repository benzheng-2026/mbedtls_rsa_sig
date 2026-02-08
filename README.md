# mbedtls_rsa_sig
# generate private key  RSA2048
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# signatue file with private key
rsa_sig.exe <filename> <private_key_file>
   