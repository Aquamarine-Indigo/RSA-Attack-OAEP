#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <gmp.h>
#include <gmpxx.h>
#include <vector>
#include <string>
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

using namespace std;

#ifndef AES_UTILS_HPP
#define AES_UTILS_HPP

const int KEY_SIZE = 16;

string vec2str(vector<unsigned char> vec) {
	string str(vec.begin(), vec.end());
	return str;
}

// string vec2hex(vector<unsigned char> vec) {
// 	stringstream ss;
// 	ss << std::hex;
// 	for(auto i : vec) {
// 		ss << (int)i;
// 	}
// 	ss << std::dec;
// 	return ss.str();
// }
string vec2hex(const std::vector<unsigned char>& vec) {
	stringstream ss;
	ss << hex << setfill('0');
	for (unsigned char byte : vec) {
		ss << setw(2) << static_cast<int>(byte);
	}
	return ss.str();
}

vector<unsigned char> hex2vec(const std::string& hex) {
	vector<unsigned char> result;
	if (hex.length() % 2 != 0) {
		throw invalid_argument("Hex string must have even length");
	}
    
	for (size_t i = 0; i < hex.length(); i += 2) {
		string byteString = hex.substr(i, 2);
		unsigned char byte = static_cast<unsigned char>(stoul(byteString, nullptr, 16));
		result.push_back(byte);
	}
	return result;
}

class AES_utils {
public:
	static vector<unsigned char> generate_key() {
		vector<unsigned char> key(KEY_SIZE);
		if (!RAND_bytes(key.data(), key.size()))
			throw std::runtime_error("Key generation failed");
		return key;
	}

	static vector<unsigned char> generate_iv() {
		vector<unsigned char> iv(KEY_SIZE);
		if (!RAND_bytes(iv.data(), iv.size()))
			throw std::runtime_error("IV generation failed");
		return iv;
	}

	static vector<unsigned char> encrypt(const vector<unsigned char>& plaintext, 
			const vector<unsigned char>& key, vector<unsigned char>& iv) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		vector<unsigned char> ciphertext(plaintext.size() + KEY_SIZE);
		int len, ciphertext_len;
		
		iv.resize(KEY_SIZE);
		if (!RAND_bytes(iv.data(), KEY_SIZE))
			throw std::runtime_error("IV generation fail");
		
		EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
		EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
		ciphertext_len = len;
		
		EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
		ciphertext_len += len;
		EVP_CIPHER_CTX_free(ctx);
		
		ciphertext.resize(ciphertext_len);
		return ciphertext;
	}

	static vector<unsigned char> decrypt(const vector<unsigned char>& ciphertext,
			const vector<unsigned char>& key, const vector<unsigned char>& iv) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		vector<unsigned char> plaintext(ciphertext.size());
		int len, plaintext_len;

		EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), iv.data());
		EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
		plaintext_len = len;

		EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
		plaintext_len += len;
		EVP_CIPHER_CTX_free(ctx);

		plaintext.resize(plaintext_len);
		return plaintext;
	}
	
	static vector<unsigned char> encrypt_string(const string& plaintext, 
			const vector<unsigned char>& key, vector<unsigned char>& iv) {
		vector<unsigned char> m_vec = vector<unsigned char>(plaintext.begin(), plaintext.end());
		cout << "PLAINTEXT hex = " << vec2hex(m_vec) << endl;
		return encrypt(m_vec, key, iv);
	}

	static void encrypt_to_mpz(mpz_t &ciphertext, const vector<unsigned char>& plaintext,
			const vector<unsigned char>& key, vector<unsigned char>& iv) {
		vector<unsigned char> cipher_vec = encrypt(plaintext, key, iv);
		vec2mpz(ciphertext, cipher_vec);
	}

	static void encrypt_to_mpz(mpz_t &ciphertext, const string& plaintext,
			const vector<unsigned char>& key, vector<unsigned char>& iv) {
		vector<unsigned char> cipher_vec = encrypt_string(plaintext, key, iv);
		vec2mpz(ciphertext, cipher_vec);
	}

	static string decrypt_to_string(const vector<unsigned char>& ciphertext,
			const vector<unsigned char>& key, const vector<unsigned char>& iv) {
		vector<unsigned char> plaintext = decrypt(ciphertext, key, iv);
		cout << "PLAINTEXT hex = " << vec2hex(plaintext) << endl;
		return string(plaintext.begin(), plaintext.end());
	}

	static string decrypt_from_mpz(const mpz_t &ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
		vector<unsigned char> cipher_vec = mpz2vec(ciphertext);
		return decrypt_to_string(cipher_vec, key, iv);
	}

	static void vec2mpz(mpz_t &ret, const vector<unsigned char>& vec) {
		mpz_import(ret, vec.size(), 1, 1, 1, 0, vec.data());
	}

	static vector<unsigned char> mpz2vec(const mpz_t &input) {
		size_t count = 0;
		unsigned char* raw = (unsigned char*)mpz_export(nullptr, &count, 1, 1, 1, 0, input);
		vector<unsigned char> result(raw, raw + count);
		free(raw);
		result.resize(count);
		return result;
	}
};

#endif // AES_UTILS_HPP