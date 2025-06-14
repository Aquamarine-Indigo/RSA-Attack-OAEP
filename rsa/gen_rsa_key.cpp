#include <iostream>
#include "GenRSA.hpp"
#include <cstdlib>
#include <fstream>

using namespace std;

int main() {
	RSAKeyPair keyPair;
	RSAPublicKey pubkey;
	Modulus modl;
	generate_RSA(1024, keyPair, pubkey, modl);

	char *modp = mpz_get_str(nullptr, 10, modl.p);
	char *modq = mpz_get_str(nullptr, 10, modl.q);

	char *keyN = mpz_get_str(nullptr, 10, keyPair.N);
	char *keyE = mpz_get_str(nullptr, 10, keyPair.e);
	char *keyD = mpz_get_str(nullptr, 10, keyPair.d);

	ofstream out_moduler("rsa_key/RSA_Moduler.txt");
	if(out_moduler.is_open()) {
		out_moduler << keyN;
		out_moduler.close();
		cerr << "Moduler file saved \"rsa_key/RSA_Moduler.txt\"" << endl;
	}
	else {
		cout << "Error opening file RSA_Moduler.txt" << endl;
		return 1;
	}

	ofstream out_p("rsa_key/RSA_p.txt");
	ofstream out_q("rsa_key/RSA_q.txt");
	if(out_p.is_open() && out_q.is_open()) {
		out_p << modp;
		out_q << modq;
		out_p.close();
		out_q.close();
		cerr << "Moduler file saved \"rsa_key/RSA_p.txt\" and \"rsa_key/RSA_q.txt\"" << endl;
	}
	else {
		cout << "Error opening file RSA_p.txt or RSA_q.txt" << endl;
		return 1;
	}
	ofstream out_pubkey("rsa_key/RSA_Public_Key.txt");
	if(out_pubkey.is_open()) {
		out_pubkey << keyN << "," << keyE;
		out_pubkey.close();
		cerr << "Public key file saved \"rsa_key/RSA_Public_Key.txt\"" << endl;
	}
	else {
		cout << "Error opening file RSA_Public_Key.txt" << endl;
		return 1;
	}
	ofstream out_privkey("rsa_key/RSA_Private_Key.txt");
	if(out_privkey.is_open()) {
		out_privkey << keyN << "," << keyD;
		out_privkey.close();
		cerr << "Private key file saved \"rsa_key/RSA_Private_Key.txt\"" << endl;
	}
	else {
		cout << "Error opening file RSA_Private_Key.txt" << endl;
		return 1;
	}
	return 0;
}