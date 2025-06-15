#ifndef server_hpp
#define server_hpp

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../rsa/GenRSA.hpp"
#include "AES_lib/AES_utils.hpp"
#include <fstream>
#include <vector>
#include <sstream>

using namespace std;

class Server {
public:
	Server(int port): server_port(port) {
		server_fd = -1;
		client_fd = -1;
		load_rsa_from_file();
	}

	~Server() {
		if(client_fd != -1) {
			close(client_fd);
		}
		if(server_fd != -1) {
			close(server_fd);
		}
	}

	void start() {
		server_fd = socket(AF_INET, SOCK_STREAM, 0);
		if(server_fd == -1) {
			perror("socket error.");
			return;
		}

		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(server_port);
		addr.sin_addr.s_addr = INADDR_ANY;
	    
		if (::bind(server_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
			perror("bind error.");
			return;
		}
	    
		if (listen(server_fd, 1) == -1) {
			perror("listening error");
			return;
		}
	    
		std::cout << "Server listening on port " << server_port << "...\n";
		exit_flag = false;
	
		while(!exit_flag) {
			client_fd = accept(server_fd, nullptr, nullptr);
			if (client_fd == -1) {
				perror("accepting error.");
				continue;
			}
		
			// handle_client(client_fd);
			handle_client_wup(client_fd);
		}
	}

private:
	int server_port;
	int server_fd;
	int client_fd;
	bool exit_flag;

	RSAKeyPair rsa_key;

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

	void handle_client(int fd) {
		uint32_t len;
		if (read(fd, &len, sizeof(len)) != sizeof(len)) {
			cerr << "Failed to read length\n";
			return;
		}
		len = ntohl(len);
	    
		string message(len, 0);
		if (read(fd, &message[0], len) != (int)len) {
			cerr << "Failed to read message\n";
			return;
		}
	    
		cerr << "Server received: " << message << "\n";

		if(message == "EXIT") {
			exit_flag = true;
			return;
		}
	    
		// Response
		string reply = "ACK: " + message;
		cout << "Server sending: " << reply << "\n";
		uint32_t reply_len = htonl(reply.size());
		write(fd, &reply_len, sizeof(reply_len));
		write(fd, reply.c_str(), reply.size());
	}

	void recv_mpz_wup(int fd, mpz_t &data_aes, vector<unsigned char> &vec_wup) {
		uint32_t total_len;
		uint32_t aes_len;
		if(recv(fd, &total_len, sizeof(total_len), MSG_WAITALL) != sizeof(total_len)) {
			cerr << "Failed to read total length\n";
			return;
		}
		total_len = ntohl(total_len);
		if(recv(fd, &aes_len, sizeof(aes_len), MSG_WAITALL) != sizeof(aes_len)) {
			cerr << "Failed to read AES length\n";
			return;
		}
		aes_len = ntohl(aes_len);

		vector<unsigned char> buffer_aes(aes_len);
		vector<unsigned char> buffer_wup(total_len - aes_len);
		if(recv(fd, buffer_aes.data(), aes_len, MSG_WAITALL) != aes_len) {
			cerr << "Failed to read AES data\n";
			return;
		}
		if(recv(fd, buffer_wup.data(), total_len - aes_len, MSG_WAITALL) != (total_len - aes_len)) {
			cerr << "Failed to read WUP data\n";
			return;
		}
		cout << "RECV:: wup hex = " << vec2hex(buffer_wup) << "\n";

		AES_utils aesutil;
		aesutil.vec2mpz(data_aes, buffer_aes);
		// aesutil.vec2mpz(data_wup, buffer_wup);
		copy(buffer_wup.begin(), buffer_wup.end(), back_inserter(vec_wup));
	}

	void handle_client_wup(int fd) {
		AES_utils aesutil;
		mpz_t data_aes;
		mpz_inits(data_aes, NULL);
		vector<unsigned char> vec_wup;
		recv_mpz_wup(fd, data_aes, vec_wup);
		cout << "Raw AES data: " << data_aes << endl;
		cout << "Raw WUP data: " << vec2hex(vec_wup) << endl;

		mpz_t decrypted_aes;
		mpz_inits(decrypted_aes, NULL);
		decrypt_RSA(decrypted_aes, data_aes, rsa_key);

		vector<unsigned char> aes_buffer = aesutil.mpz2vec(decrypted_aes);
		int aes_key_len = aes_buffer.size() >> 1;
		vector<unsigned char> aes_iv(aes_buffer.begin(), aes_buffer.begin() + aes_key_len);
		vector<unsigned char> aes_key(aes_buffer.begin() + aes_key_len, aes_buffer.end());

		mpz_t aes_key_mpz, aes_iv_mpz;
		mpz_inits(aes_key_mpz, aes_iv_mpz, NULL);
		aesutil.vec2mpz(aes_key_mpz, aes_key);
		aesutil.vec2mpz(aes_iv_mpz, aes_iv);
		cout << "-> AES key: " << aes_key_mpz << endl;
		cout << "-> AES IV: " << aes_iv_mpz << endl;

		// vector<unsigned char> wup_buffer = aesutil.mpz2vec(data_wup);
		// string raw_wup = string(wup_buffer.begin(), wup_buffer.end());
		// string decrypted_wup = aesutil.decrypt_to_string(wup_buffer, aes_key, aes_iv);
		string decrypted_wup = aesutil.decrypt_to_string(vec_wup, aes_key, aes_iv);
		// mpz_t decrypted_wup_mpz;
		// mpz_inits(decrypted_wup_mpz, NULL);
		// mpz_set_str(decrypted_wup_mpz, decrypted_wup.c_str(), 10);
		// cout << "Decrypted WUP mpz: " << decrypted_wup_mpz << endl;

		// cout << "Raw WUP message: " << data_wup << endl;
		cout << "Decrypted WUP (discard first 16 bytes): " << decrypted_wup.substr(16) << endl;

		stringstream ss;
		ss << "###" << endl;
		ss << "Encrypted AES (IV||Key):" << data_aes << endl;
		ss << "Encrypted WUP by AES:" << vec2hex(vec_wup) << endl;

		fstream fout;
		fout.open("history/server_history.txt", ios::out | ios::app);
		fout << ss.str();
		fout.close();

		mpz_clears(data_aes, aes_key_mpz, aes_iv_mpz, NULL);
	}
};

#endif