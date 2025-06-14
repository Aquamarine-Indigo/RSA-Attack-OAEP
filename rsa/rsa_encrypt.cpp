#include <iostream>
#include <cstring>
#include <fstream>
#include "GenRSA.hpp"
using namespace std;

int main(){
	// Using public key
	ifstream inkey("rsa_key/RSA_Public_Key.txt");
	if(!inkey){
	        cerr << "Error: Unable to open RSA public key file" << endl;
		return 1;
	}
	string key_line;
	if(!getline(inkey, key_line)){
	        cerr << "Error: Unable to read RSA public key file" << endl;
		return 1;
	}

	int comma_pos = key_line.find(",");
	if(comma_pos == string::npos){
	        cerr << "Error: Invalid RSA public key file" << endl;
		return 1;
	}

	string str_n = key_line.substr(0, comma_pos);
	string str_e = key_line.substr(comma_pos+1);

	RSAPublicKey rsa_pub_key;
	mpz_set_str(rsa_pub_key.N, str_n.c_str(), 10);
	mpz_set_str(rsa_pub_key.key, str_e.c_str(), 10);

	cout << "Finished setting RSA public key.\n";

	ifstream intext("rsa_encryption/Raw_Message.txt");
	if(!intext){
	        cerr << "Error: Unable to open raw message file" << endl;
		return 1;
	}
	string text_str;
	if(!getline(intext, text_str)){
	        cerr << "Error: Unable to read raw message file" << endl;
		return 1;
	}
	mpz_t plaintext;
	mpz_init(plaintext);
	mpz_set_str(plaintext, text_str.c_str(), 16);

	cout << "Finished reading raw message.\n";

	mpz_t ciphertext;
	mpz_init(ciphertext);
	encrypt_RSA(ciphertext, plaintext, rsa_pub_key);
	cout << "Finished encrypting.\n";
	cout << "Ciphertext: " << ciphertext << endl;

	ofstream outcipher("rsa_encryption/Encrypted_Message.txt");
	char *cipher_hex = mpz_get_str(NULL, 16, ciphertext);
	if(!outcipher.is_open()){
	        cerr << "Error: Unable to open encrypted message file" << endl;
		return 1;
	}
	outcipher << cipher_hex;
	outcipher.close();
	cout << "Finished writing encrypted message.\n";

	return 0;
}