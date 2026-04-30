echo do you really want to generate certificate and shit?
read choice 
if [[ $choice == "y" ]]; then
openssl ecparam -name secp256r1 -genkey -outform DER -out key.der
openssl req -new -x509 -days 365 -key "key.der" -sha256 -outform DER -out cert.der
fi
