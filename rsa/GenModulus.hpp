#include <iostream>
#include <cmath>
#include <cstdio>
#include <chrono>
using namespace std;

#ifndef GenModulus_hpp
#define GenModulus_hpp

using u64 = uint64_t;
using u32 = uint32_t;
// using u128 = uint128_t;

// Small prime numbers
u64 mod_pow(u64 base, u64 index, u64 mod) {
	u64 result = 1;
	while(index > 0) {
	        if(index & 1) {
			result = (u64(result) * base) % mod;
	        }
		base = (u64(base) * base) % mod;
		index >>= 1;
	}
	return result;
}

bool is_prime(u64 n, int iterations = 5) {
	// Miller-Rabin primality test
	// iterations = 3 * n^2
	if (n < 4) {
		return n == 2 || n == 3;
	}
	u64 d = n - 1;
	int r = 0;
	while((d & 1) == 0) {
		d >>= 1;
		++r;
	}
    
	static mt19937_64 rng(chrono::steady_clock::now().time_since_epoch().count());
	uniform_int_distribution<u64> dist(2, n - 2);
    
	for(int i = 0; i < iterations; ++i) {
		u64 a = dist(rng);
		u64 x = mod_pow(a, d, n);
		if (x == 1 || x == n - 1)
			continue;
		bool continue_outer = false;
		for(int j = 0; j < r - 1; ++j) {
			x = (u64(x) * x) % n;
			if (x == n - 1) {
				continue_outer = true;
				break;
			}
		}
		if (continue_outer)
			continue;
		return false;
	}
	return true;
}

u64 generate_prime(u64 min = u64(1000000007), u64 max = u64((1ull<<62)+(1ull<<31))) {
	static mt19937_64 rng(chrono::steady_clock::now().time_since_epoch().count());
	uniform_int_distribution<u64> dist(min, max);
	u64 p = dist(rng) | 1; // making it odd
	while(is_prime(p) == false) {
		p = dist(rng) | 1;
	}
	return p;
}

u64 modular_inverse(u64 a, u64 m) {
	// d * a == 1 (mod m)
	u64 m0 = m;
	u64 t, q;
	u64 x0 = 0, x1 = 1;
	while (a > 1) {
		q = a / m;
		t = m;
		m = a % m;
		// a = t * q + m
		a = t;
		t = x0;
		x0 = x1 - q * x0;
		x1 = t;
	}
	if(x1 < 0)
		return x1 + m0;
	return x1;
}

// Large prime numbers

#include <gmp.h>
#include <gmpxx.h>

void generate_large_prime(mpz_t prime, gmp_randstate_t state, unsigned int bits) {
	mpz_urandomb(prime, state, bits);
	mpz_nextprime(prime, prime);
}

#endif