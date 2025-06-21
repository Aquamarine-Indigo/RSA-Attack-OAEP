g++ gen_plaintext.cpp -o gen_plaintext -std=c++17 -O2 -lgmp -lgmpxx -lssl -lcrypto \
	-L/opt/homebrew/Cellar/gmp/6.3.0/lib \
	-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib \
	-I/opt/homebrew/Cellar/gmp/6.3.0/include \
	-I/opt/homebrew/Cellar/openssl@3/3.5.0/include 
./gen_plaintext

echo ENCRYPT
g++ rsa_encrypt.cpp -o rsa_encrypt -std=c++17 -O2 -lgmp -lgmpxx -lssl -lcrypto \
	-L/opt/homebrew/Cellar/gmp/6.3.0/lib \
	-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib \
	-I/opt/homebrew/Cellar/gmp/6.3.0/include \
	-I/opt/homebrew/Cellar/openssl@3/3.5.0/include 

echo DECRYPT
g++ rsa_decrypt.cpp -o rsa_decrypt -std=c++17 -O2 -lgmp -lgmpxx -lssl -lcrypto \
	-L/opt/homebrew/Cellar/gmp/6.3.0/lib \
	-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib \
	-I/opt/homebrew/Cellar/gmp/6.3.0/include \
	-I/opt/homebrew/Cellar/openssl@3/3.5.0/include 

echo ----Encryption----
./rsa_encrypt
echo ----Decryption----
./rsa_decrypt