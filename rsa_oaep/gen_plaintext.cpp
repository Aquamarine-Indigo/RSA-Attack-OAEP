#include <iostream>
#include "RSA_OAEP.hpp"
#include <cstdlib>
#include <fstream>

int main() {
	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, time(NULL));
	mpz_t plaintext;
	mpz_init(plaintext);
	mpz_urandomb(plaintext, state, 480);

	char *plaintext_str = mpz_get_str(NULL, 16, plaintext);
	ofstream file;
	file.open("rsa_encryption/Raw_Message.txt");
	file << plaintext_str;
	file.close();
	return 0;
}