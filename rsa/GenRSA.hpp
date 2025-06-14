#include <iostream>
#include <random>
#include <chrono>
#include <cmath>
#include <cstdio>

#include <gmp.h>
#include <gmpxx.h>
#include "GenModulus.hpp"
using namespace std;

#ifndef GenRSA_hpp
#define GenRSA_hpp

using u64 = uint64_t;
using u32 = uint32_t;
// using u128 = uint128_t;

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

struct RSASecretKey {
	mpz_t N, key;

	RSASecretKey() {
		mpz_inits(N, key, NULL);
	}

	void set_value(mpz_t N_, mpz_t key_) {
		mpz_set(N, N_);
		mpz_set(key, key_);
	}

	~RSASecretKey() {
		mpz_clears(N, key, NULL);
	}
};

void generate_RSA(u32 bits, RSAKeyPair& keypair_, RSAPublicKey& pubkey_, Modulus& modulus_) {
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

	// mpz_set(modulus_.N, keypair.N);
	// mpz_set(modulus_.p, p);
	// mpz_set(modulus_.q, q);
	// mpz_set(keypair_.d, keypair.d);
	// mpz_set(keypair_.e, keypair.e);
	// mpz_set(keypair_.N, keypair.N);
	// mpz_set(pubkey_.key, pubkey.key);
	// mpz_set(pubkey_.N, pubkey.N);
	keypair_.set_value(keypair.N, keypair.e, keypair.d);
	pubkey_.set_value(pubkey.N, pubkey.key);
	modulus_.set_value(keypair.N, p, q);
}

void encrypt_RSA(mpz_t c, const mpz_t m, const RSAPublicKey& pubkey) {
	mpz_powm(c, m, pubkey.key, pubkey.N);
}


void decrypt_RSA(mpz_t m, const mpz_t c, const RSAKeyPair& keypair) {
	mpz_powm(m, c, keypair.d, keypair.N);
}

void decrypt_RSA(mpz_t m, const mpz_t c, const RSASecretKey& sk) {
	mpz_powm(m, c, sk.key, sk.N);
}

#endif