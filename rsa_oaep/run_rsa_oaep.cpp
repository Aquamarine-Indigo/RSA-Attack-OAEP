#include <iostream>
#include "RSA_OAEP.hpp"
using namespace std;

int main() {
	RSAKeyPair keyPair;
	RSAPublicKey pubkey;
	Modulus modl;
	generate_RSA(1024, keyPair, pubkey, modl);
	cout << "Max message size: " << MAX_MESSAGE_SIZE << endl;

	cout << "Generated key: " << endl;
	cout << "\t-> N = " << keyPair.N << endl;
	cout << "\t-> e = " << keyPair.e << endl;
	cout << "\t-> d = " << keyPair.d << endl;

	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, time(NULL));
	mpz_t plaintext;
	mpz_init(plaintext);
	mpz_urandomb(plaintext, state, 480);

	cout << "\nEncryption: " << endl;
	cout << "\n-> Plaintext: " << plaintext << endl;
	mpz_t ciphertext;
	mpz_init(ciphertext);
	encrypt_RSA(ciphertext, plaintext, pubkey);
	cout << "\n-> Ciphertext: " << ciphertext << endl;

	mpz_t decrypted;
	mpz_init(decrypted);
	decrypt_RSA(decrypted, ciphertext, keyPair);
	cout << "\n-> Decrypted: " << decrypted << endl;

	mpz_clears(plaintext, ciphertext, decrypted, NULL);
	gmp_randclear(state);
	return 0;
}