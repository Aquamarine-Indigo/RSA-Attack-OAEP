#include "../rsa/GenRSA.hpp"
#include "../server_client/AES_lib/AES_utils.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <gmp.h>
#include <gmpxx.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>
#include <memory>
#include <iomanip>
using namespace std;

// struct mpz_deleter {
// 	void operator()(mpz_t* ptr) const {
// 		mpz_clear(*ptr);
// 		delete ptr;
// 	}
// };
// using mpz_ptr_ = unique_ptr<mpz_t, mpz_deleter>;

// mpz_ptr_ mpz_ptr_from_str(const string &str) {
// 	// mpz_ptr_ n_ptr(new mpz_t);
// 	// mpz_init(*n_ptr);
// 	// mpz_set_str(*n_ptr, str.c_str(), 10);
// 	// return n_ptr;
// 	auto n_ptr = make_unique<mpz_t>();
// 	mpz_init(*n_ptr);
// 	mpz_set_str(*n_ptr, str.c_str(), 10);
// 	return n_ptr;
// }

class int_gmp {
public:
	mpz_t value;

	int_gmp() {
		mpz_init(value);
	}

	int_gmp(const string &str) {
		mpz_init(value);
		mpz_set_str(value, str.c_str(), 10);
	}

	int_gmp(const int_gmp &other) {
		mpz_init(value);
		mpz_set(value, other.value);
	}

	int_gmp& operator=(const int_gmp& other) {
		if (this != &other)
			mpz_set(value, other.value);
		return *this;
	}

	~int_gmp() { mpz_clear(value); }
};

/**

CCA2 Attack:
- Attacker can decrypt the message by using the public key and the ciphertext. 
- The attacker can use the decryption oracle for ciphertexts apart from the target.

Textbook RSA: c = m^e mod n; m = c^d mod n
- a history c1 = m1^e mod n
- a chosen cipher c2 = m2^e mod n
- Target: decrypt m1
- Attack: c1 * c2 = (m1^e mod n) * (m2^e mod n) = (m1 * m2)^e mod n
	- c' = c1 * c2
	- use the decryption oracle to decrypt c' to get m' = m1 * m2
	- m1 = m' * (m2)^-1 mod n
	- (m2)^-1 is the inverse of m2 modulo n

 */

class Attacker {
public:
	Attacker() {
		load_rsa_from_file();
		load_rsa_pub_from_file();

		cipher_vec.clear();
		aes_cipher.clear();
		read_history(cipher_vec, aes_cipher);
		int n_history = cipher_vec.size();
		printf("Number of history: %d\n", n_history);

		// for(int i = 0; i < n_history; i++) {
		// 	cout << "--[" << i << "]-- ";
		// 	cout << cipher_vec[i].value << endl;
		// }
	}

	void attack() {
		int n_history = cipher_vec.size();
		for(int i = 0; i < n_history; i++) {
			mpz_t result;
			mpz_init(result);
			attack_once(cipher_vec[i].value, result);
			cout << "-> Ciphertext: " << cipher_vec[i].value << endl;
			cout << "-> Plaintext:  " << result << endl << endl;
			mpz_clear(result);
		}
	}

private:
	RSAPublicKey pubkey;
	RSAKeyPair rsa_key;
	vector<int_gmp> cipher_vec;
	vector<string> aes_cipher;
	
	void load_rsa_pub_from_file() {
		// Using public key
		ifstream inkey("../rsa/rsa_key/RSA_Public_Key.txt");
		if(!inkey){
			cerr << "Error: Unable to open RSA public key file" << endl;
			return;
		}
		string key_line;
		if(!getline(inkey, key_line)){
			cerr << "Error: Unable to read RSA public key file" << endl;
			return;
		}

		int comma_pos = key_line.find(",");
		if(comma_pos == string::npos){
			cerr << "Error: Invalid RSA public key file" << endl;
			return;
		}

		string str_n = key_line.substr(0, comma_pos);
		string str_e = key_line.substr(comma_pos+1);

		mpz_set_str(pubkey.N, str_n.c_str(), 10);
		mpz_set_str(pubkey.key, str_e.c_str(), 10);
		cout << "RSA Moduler: " << pubkey.N << endl;
		cout << "RSA public key: " << pubkey.key << endl;
	}

	void load_rsa_from_file() {
		// Using public key
		ifstream inkey("../rsa/rsa_key/RSA_Public_Key.txt");
		if(!inkey){
			cerr << "Error: Unable to open RSA public key file" << endl;
			return;
		}
		string key_line;
		if(!getline(inkey, key_line)){
			cerr << "Error: Unable to read RSA public key file" << endl;
			return;
		}

		int comma_pos = key_line.find(",");
		if(comma_pos == string::npos){
			cerr << "Error: Invalid RSA public key file" << endl;
			return;
		}

		string str_n = key_line.substr(0, comma_pos);
		string str_e = key_line.substr(comma_pos+1);

		// Using private key
		ifstream insk("../rsa/rsa_key/RSA_Private_Key.txt");
		if(!insk){
			cerr << "Error: Unable to open RSA private key file" << endl;
			return;
		}
		string key_line_sk;
		if(!getline(insk, key_line_sk)){
			cerr << "Error: Unable to read RSA private key file" << endl;
			return;
		}

		int comma_pos_sk = key_line_sk.find(",");
		if(comma_pos_sk == string::npos){
			cerr << "Error: Invalid RSA private key file" << endl;
			return;
		}

		string str_d = key_line_sk.substr(comma_pos_sk+1);

		mpz_set_str(rsa_key.N, str_n.c_str(), 10);
		mpz_set_str(rsa_key.e, str_e.c_str(), 10);
		mpz_set_str(rsa_key.d, str_d.c_str(), 10);
		cout << "RSA Moduler: " << rsa_key.N << endl;
		cout << "RSA public key: " << rsa_key.e << endl;
		cout << "RSA private key: " << rsa_key.d << endl;
	}

	void read_history(vector<int_gmp> &c_vec, vector<string> &aes_ciphers) {
		ifstream inputfile("../server_client/history/server_history.txt");
		if(!inputfile) {
			cerr << "Error: Unable to open history file" << endl;
			return;
		}
		string line;
		while(getline(inputfile, line)) {
			if(line.empty())
				continue;
			if(line.substr(0, 3) == "###")
				continue;
			if(line.substr(0, 13) == "Encrypted AES") {
				int sep_pos = line.find(":");
				if(sep_pos == string::npos) {
					cerr << "Error: Invalid history file" << endl;
					return;
				}
				string ciphertext_str = line.substr(sep_pos+1);
				// mpz_t ciphertext_mpz;
				// mpz_init(ciphertext_mpz);
				// mpz_set_str(ciphertext_mpz, ciphertext_str.c_str(), 10);
				// c_vec.push_back(ciphertext_mpz);
				c_vec.push_back(int_gmp(ciphertext_str));
			}
			else if(line.substr(0, 13) == "Encrypted WUP") {
				int sep_pos = line.find(":");
				if(sep_pos == string::npos) {
					cerr << "Error: Invalid history file" << endl;
					return;
				}
				string wup_ciphertext = line.substr(sep_pos+1);
				aes_ciphers.push_back(wup_ciphertext);
			}
		}
	}

	void attack_once(const mpz_t &target, mpz_t &result) {
		// target c1->m1, chosen m2->c2, m1 unknown
		mpz_t chosen_cipher, cc_inverse, cc_cipher;
		mpz_inits(chosen_cipher, cc_inverse, cc_cipher, NULL);
		mpz_set_ui(chosen_cipher, 2);
		mpz_invert(cc_inverse, chosen_cipher, rsa_key.N);

		encrypt_RSA(cc_cipher, chosen_cipher, pubkey);

		// c' = c1 * c2
		mpz_t cc_mul, cc_mul_decrypt;
		mpz_inits(cc_mul, cc_mul_decrypt, NULL);
		mpz_mul(cc_mul, target, cc_cipher);
		
		decrypt_RSA(cc_mul_decrypt, cc_mul, rsa_key);

		// m' = c'^d mod N = m1 * m2
		mpz_mul(result, cc_mul_decrypt, cc_inverse);
		mpz_mod(result, result, rsa_key.N);

		mpz_clears(chosen_cipher, cc_inverse, cc_cipher, cc_mul, cc_mul_decrypt, NULL);
	}
};