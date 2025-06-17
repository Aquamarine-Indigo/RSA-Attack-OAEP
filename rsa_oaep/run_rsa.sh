g++ run_rsa_oaep.cpp -o run_rsa_oaep -std=c++17 -O2 -lgmp -lgmpxx -lssl -lcrypto \
	-L/opt/homebrew/Cellar/gmp/6.3.0/lib \
	-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib \
	-I/opt/homebrew/Cellar/gmp/6.3.0/include \
	-I/opt/homebrew/Cellar/openssl@3/3.5.0/include 

./run_rsa_oaep