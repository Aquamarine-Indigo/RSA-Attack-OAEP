#include <iostream>
#include <cstring>
#include <fstream>
#include "GenRSA.hpp"
using namespace std;

int main(){
	// Using public key
	ifstream inkey("rsa_key/RSA_Private_Key.txt");
	if(!inkey){
	        cerr << "Error: Unable to open RSA secret key file" << endl;
		return 1;
	}
	string key_line;
	if(!getline(inkey, key_line)){
	        cerr << "Error: Unable to read RSA secret key file" << endl;
		return 1;
	}

	int comma_pos = key_line.find(",");
	if(comma_pos == string::npos){
	        cerr << "Error: Invalid RSA secret key file" << endl;
		return 1;
	}

	string str_n = key_line.substr(0, comma_pos);
	string str_d = key_line.substr(comma_pos+1);

	RSASecretKey rsa_sec_key;
	mpz_set_str(rsa_sec_key.N, str_n.c_str(), 10);
	mpz_set_str(rsa_sec_key.key, str_d.c_str(), 10);

	cout << "Finished setting RSA secret key.\n";

	ifstream intext("rsa_encryption/Encrypted_Message.txt");
	if(!intext){
	        cerr << "Error: Unable to open encrypted message file" << endl;
		return 1;
	}
	string text_line;
	if(!getline(intext, text_line)){
	        cerr << "Error: Unable to read raw message file" << endl;
		return 1;
	}
	mpz_t ciphertext;
	mpz_init(ciphertext);
	mpz_set_str(ciphertext, text_line.c_str(), 16);

	cout << "Finished reading encrypted message.\n";

	mpz_t plaintext;
	mpz_init(plaintext);
	decrypt_RSA(plaintext, ciphertext, rsa_sec_key);
	cout << "Finished decrypting.\n";
	cout << "Plaintext: " << plaintext << endl;

	char *plaintext_16 = mpz_get_str(NULL, 16, plaintext);
	cout << "Plaintext in hex: " << plaintext_16 << endl;

	return 0;
}