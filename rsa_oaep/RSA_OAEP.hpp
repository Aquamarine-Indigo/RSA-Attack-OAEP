#include <gmpxx.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <sstream>

using namespace std;

const size_t RSA_KEY_SIZE = 1024;
const size_t HASH_SIZE = SHA256_DIGEST_LENGTH;
// const size_t HASH_LEN = 32;
const size_t RSA_BYTE_SIZE = RSA_KEY_SIZE / 8;
const size_t MAX_MESSAGE_SIZE = RSA_BYTE_SIZE - 2 * HASH_SIZE - 2; // 62
const string lhash_label = " ";
const size_t DATA_BLOCK_LEN = RSA_BYTE_SIZE - HASH_SIZE - 1;

// Mask Generation Function 1
vector<unsigned char> mgf1(const vector<unsigned char> &seed, size_t maskLen) {
	vector<unsigned char> mask;
	unsigned char counter[4] = {0, 0, 0, 0};

	for (size_t i = 0; mask.size() < maskLen; ++i) {
		counter[3] = i & 0xFF;
		counter[2] = (i >> 8) & 0xFF;
		counter[1] = (i >> 16) & 0xFF;
		counter[0] = (i >> 24) & 0xFF;

		vector<unsigned char> data(seed);
		data.insert(data.end(), counter, counter + 4);

		unsigned char hash[HASH_SIZE];
		SHA256(data.data(), data.size(), hash);

		mask.insert(mask.end(), hash, hash + HASH_SIZE);
	}
	mask.resize(maskLen);
	return mask;
}

struct Modulus {
	mpz_t N, p, q;
	Modulus() {
		mpz_inits(N, p, q, NULL);
	}
	void set_value(mpz_t N_, mpz_t p_, mpz_t q_) {
		mpz_set(N, N_);
		mpz_set(p, p_);
		mpz_set(q, q_);
	}
	~Modulus() {
		mpz_clears(N, p, q, NULL);
	}
};

struct RSAKeyPair {
	mpz_t N, e, d;

	RSAKeyPair() {
		mpz_inits(N, e, d, NULL);
	}

	void set_value(mpz_t N_, mpz_t e_, mpz_t d_) {
		mpz_set(N, N_);
		mpz_set(e, e_);
		mpz_set(d, d_);
	}

	~RSAKeyPair() {
		mpz_clears(N, e, d, NULL);
	}
};

struct RSAPublicKey {
	mpz_t N, key;

	RSAPublicKey() {
		mpz_inits(N, key, NULL);
	}

	void set_value(mpz_t N_, mpz_t key_) {
		mpz_set(N, N_);
		mpz_set(key, key_);
	}

	~RSAPublicKey() {
		mpz_clears(N, key, NULL);
	}
};

struct RSAPrivateKey {
	mpz_t N, key;

	RSAPrivateKey() {
		mpz_inits(N, key, NULL);
	}

	void set_value(mpz_t N_, mpz_t key_) {
		mpz_set(N, N_);
		mpz_set(key, key_);
	}

	~RSAPrivateKey() {
		mpz_clears(N, key, NULL);
	}
};

void vec2mpz(mpz_t &ret, const vector<unsigned char>& vec) {
	mpz_import(ret, vec.size(), 1, 1, 1, 0, vec.data());
}

vector<unsigned char> mpz2vec(const mpz_t &input) {
	size_t count = 0;
	unsigned char* raw = (unsigned char*)mpz_export(nullptr, &count, 1, 1, 1, 0, input);
	vector<unsigned char> result(raw, raw + count);
	free(raw);
	return result;
}

vector<unsigned char> mpz2vec_len(const mpz_t &input, size_t len) {
	size_t count = 0;
	unsigned char* raw = (unsigned char*)mpz_export(nullptr, &count, 1, 1, 1, 0, input);
	vector<unsigned char> result(len, 0);
	std::copy(raw, raw + count, result.begin()+(len-count));
	free(raw);
	return result;
}

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

void generate_large_prime(mpz_t prime, gmp_randstate_t state, unsigned int bits) {
	mpz_urandomb(prime, state, bits);
	mpz_nextprime(prime, prime);
}

void generate_RSA(uint32_t bits, RSAKeyPair& keypair_, RSAPublicKey& pubkey_, Modulus& modulus_) {
	RSAKeyPair keypair;
	RSAPublicKey pubkey;
	mpz_t phi_N, p, q, p_1, q_1;

	gmp_randstate_t state;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, time(NULL));

        generate_large_prime(p, state, bits>>1);
	generate_large_prime(q, state, bits>>1);
	mpz_mul(keypair.N, p, q);
	// N = p * q

	mpz_sub_ui(p_1, p, 1);
	mpz_sub_ui(q_1, q, 1);
	mpz_mul(phi_N, p_1, q_1);
	// phi(N) = (p-1)*(q-1)

	mpz_set_ui(keypair.e, 65537);

	mpz_set(pubkey.key, keypair.e);
	mpz_set(pubkey.N, keypair.N);
	// Compute private exponent d = e^{-1} mod phi
	if (mpz_invert(keypair.d, keypair.e, phi_N) == 0) {
		std::cerr << "Error computing modular inverse (e, phi)." << std::endl;
		return;
	}
	mpz_clears(p, q, p_1, q_1, phi_N, NULL);
	gmp_randclear(state);

	keypair_.set_value(keypair.N, keypair.e, keypair.d);
	pubkey_.set_value(pubkey.N, pubkey.key);
	modulus_.set_value(keypair.N, p, q);
}

vector<unsigned char> encoding_OAEP(const vector<unsigned char> &message, vector<unsigned char> &rand_seed) {
	// n = 1024/8 = 128 (RSA key length in bytes)
	// k0 = HASH_SIZE
	// k1 = MAX_MESSAGE_SIZE - message.size() = ps_len
	if(message.size() > MAX_MESSAGE_SIZE) {
		throw std::runtime_error("Message too large");
	}

	unsigned char lhash[HASH_SIZE];
	SHA256((const unsigned char *)lhash_label.data(), lhash_label.size(), lhash);

	// format: PS || 0x01 || M
	int ps_len = MAX_MESSAGE_SIZE - message.size();
	vector<unsigned char> data_block(lhash, lhash + HASH_SIZE);
	data_block.insert(data_block.end(), ps_len, 0x00);
	data_block.insert(data_block.end(), 0x01);
	data_block.insert(data_block.end(), message.begin(), message.end());
	
	// vector<unsigned char> rand_seed(HASH_SIZE);
	for(int i = 0; i < HASH_SIZE; i++) {
		rand_seed[i] = rand() % 256;
	}

	// X = m000 XOR MGF1(seed, n-k0)
	vector<unsigned char> seed_g_mask = mgf1(rand_seed, DATA_BLOCK_LEN);
	vector<unsigned char> x_result(DATA_BLOCK_LEN);
	for(int i = 0; i < RSA_BYTE_SIZE - HASH_SIZE - 1; i++) {
		x_result[i] = data_block[i] ^ seed_g_mask[i];
	}

	// Y = seed XOR MGF1(X, k0)
	vector<unsigned char> data_h_mask = mgf1(x_result, HASH_SIZE);
	vector<unsigned char> y_result(HASH_SIZE);
	for(int i = 0; i < HASH_SIZE; i++) {
		y_result[i] = data_h_mask[i] ^ rand_seed[i];
	}

	vector<unsigned char> result;
	result.push_back(0x00);
	result.insert(result.end(), y_result.begin(), y_result.end());
	result.insert(result.end(), x_result.begin(), x_result.end());

	cout << "\n>>> Encoded message: " << vec2hex(result) << endl;
	cout << ">>> Hash lhash: " << vec2hex(vector<unsigned char>(lhash, lhash + HASH_SIZE)) << endl;
	cout << ">>> data_block: " << vec2hex(data_block) << endl;
	cout << ">>> seed: " << vec2hex(rand_seed) << endl;
	cout << ">>> seed_g_mask: " << vec2hex(seed_g_mask) << endl;
	cout << ">>> data_h_mask: " << vec2hex(data_h_mask) << endl;
	cout << ">>> X: " << vec2hex(x_result) << endl;
	cout << ">>> Y: " << vec2hex(y_result) << endl;
	return result;
}

vector<unsigned char> decoding_OAEP(const vector<unsigned char> &encoded_message) {
	// r = Y XOR MGF1(X, k0)
	// m000 = X XOR MGF1(r, n-k0)
	cout << "\n<<< Encoded message: " << vec2hex(encoded_message) << endl;
	if (encoded_message.size() < 2 * HASH_SIZE + 2) {
		throw invalid_argument("Error: Encoded message size is too short");
	}
	if(encoded_message[0] != 0x00) {
		throw invalid_argument("Error: Encoded message does not start with 0x00");
	}

	vector<unsigned char> y_result(encoded_message.begin() + 1, encoded_message.begin() + 1 + HASH_SIZE);
	vector<unsigned char> x_result(encoded_message.begin() + 1 + HASH_SIZE, encoded_message.end());
	cout << ">>> X: " << vec2hex(x_result) << endl;
	cout << ">>> Y: " << vec2hex(y_result) << endl;

	vector<unsigned char> rand_seed(HASH_SIZE);
	vector<unsigned char> mgf_x = mgf1(x_result, HASH_SIZE);
	for(int i = 0; i < HASH_SIZE; i++) {
		rand_seed[i] = y_result[i] ^ mgf_x[i];
	}

	vector<unsigned char> data_block(DATA_BLOCK_LEN);
	vector<unsigned char> mgf_y = mgf1(rand_seed, DATA_BLOCK_LEN);
	for(int i = 0; i < RSA_BYTE_SIZE - HASH_SIZE; i++) {
	        data_block[i] = x_result[i] ^ mgf_y[i];
	}

	cout << ">>> data_block: " << vec2hex(data_block) << endl;
	cout << ">>> seed: " << vec2hex(rand_seed) << endl;
	cout << ">>> mgf_x: " << vec2hex(mgf_x) << endl;
	cout << ">>> mgf_y: " << vec2hex(mgf_y) << endl;
	cout << "!!! mgf_x == data_x_mask\n";

	unsigned char lhash[HASH_SIZE];
	SHA256((const unsigned char*)lhash_label.data(), lhash_label.size(), lhash);

	if (std::equal(data_block.begin(), data_block.begin() + HASH_SIZE, lhash) == false) {
		cout << ">>> Hash mismatched: found    " << vec2hex(vector<unsigned char>(data_block.begin(), data_block.begin() + HASH_SIZE)) << endl;
		cout << ">>> Hash mismatched: expected " << vec2hex(vector<unsigned char>(lhash, lhash + HASH_SIZE)) << endl;
		throw std::runtime_error("Error: Hash mismatched.");
	}

	vector<unsigned char>::iterator it = std::find(data_block.begin() + HASH_SIZE, data_block.end(), 0x01);
	if (it == data_block.end())
		throw std::runtime_error("Error: No 0x01 found in encoded message.");
	return vector<unsigned char>(it + 1, data_block.end());
}

void encrypt_RSA(mpz_t &c, const mpz_t &m, const RSAPublicKey& pk, bool save_seed=false) {
	vector<unsigned char> message_vec = mpz2vec(m);
	vector<unsigned char> rand_seed(HASH_SIZE);
	vector<unsigned char> oaep_message = encoding_OAEP(message_vec, rand_seed);
	mpz_t oaep_message_mpz;
	mpz_init(oaep_message_mpz);
	vec2mpz(oaep_message_mpz, oaep_message);
	mpz_powm(c, oaep_message_mpz, pk.key, pk.N);

	if(save_seed == true) {
		ofstream outfile;
		outfile.open("rsa_encryption/Random_Number.txt");
		outfile << vec2hex(rand_seed);
		outfile.close();

		outfile.open("rsa_encryption/Message_After_Padding.txt");
		outfile << vec2hex(oaep_message);
		outfile.close();
	}
}

void decrypt_RSA(mpz_t &m, const mpz_t &c, const RSAPrivateKey& sk) {
	mpz_t oaep_message_mpz;
	mpz_init(oaep_message_mpz);
	mpz_powm(oaep_message_mpz, c, sk.key, sk.N);
	vector<unsigned char> oaep_message = mpz2vec_len(oaep_message_mpz, RSA_BYTE_SIZE);
	vector<unsigned char> message_vec = decoding_OAEP(oaep_message);
	vec2mpz(m, message_vec);
}

void decrypt_RSA(mpz_t &m, const mpz_t &c, const RSAKeyPair& rsa_key) {
	mpz_t oaep_message_mpz;
	mpz_init(oaep_message_mpz);
	mpz_powm(oaep_message_mpz, c, rsa_key.d, rsa_key.N);
	vector<unsigned char> oaep_message = mpz2vec_len(oaep_message_mpz, RSA_BYTE_SIZE);
	vector<unsigned char> message_vec = decoding_OAEP(oaep_message);
	vec2mpz(m, message_vec);
}