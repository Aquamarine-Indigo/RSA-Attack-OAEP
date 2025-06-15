#include <iostream>
#include <cstring>
#include "AES_utils.hpp"
#include <vector>
using namespace std;

int main() {
	AES_utils aes;
	string line_str;
	auto key = aes.generate_key();
	auto iv = aes.generate_iv();
	cout << "Key: " << vec2str(key) << endl;
	cout << "IV: " << vec2str(iv) << endl;
	while(true) {
		cout << "> ";
		getline(cin, line_str);
		if(line_str == "exit") {
			break;
		}
		else if(line_str.substr(0, 7) == "encrypt") {
			string plaintext = line_str.substr(8);
			cout << "Encrypt target: " << plaintext << endl;
			// vector<unsigned char> m_vec(plaintext.begin(), plaintext.end());
			// auto ciphertext = aes.encrypt(m_vec, key, iv);
			mpz_t ciphertext;
			mpz_init(ciphertext);
			aes.encrypt_to_mpz(ciphertext, plaintext, key, iv);
			// cout << "Ciphertext: " << vec2str(ciphertext) << endl;
			cout << "Ciphertext: " << ciphertext << endl;
		}
		else if(line_str.substr(0, 7) == "decrypt") {
			string ciphertext = line_str.substr(8);
			cout << "Decrypt target: " << ciphertext << endl;
			// vector<unsigned char> c_vec(ciphertext.begin(), ciphertext.end());
			// auto plaintext = aes.decrypt(c_vec, key, iv);
			// cout << "Plaintext: " << vec2str(plaintext) << endl;
			mpz_t cipher_mpz;
			mpz_init(cipher_mpz);
			mpz_set_str(cipher_mpz, ciphertext.c_str(), 10);
			string plaintext = aes.decrypt_from_mpz(cipher_mpz, key, iv);
			cout << "Plaintext: " << plaintext << endl;
		}
		else if(line_str.substr(0, 5) == "regen") {
			key = aes.generate_key();
			iv = aes.generate_iv();
			cout << "Key: " << vec2str(key) << endl;
			cout << "IV: " << vec2str(iv) << endl;
		}
	}
}