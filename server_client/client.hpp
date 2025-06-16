#ifndef client_hpp
#define client_hpp
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <fstream>
#include <vector>
#include <ctime>
#include <sstream>

#include "../rsa/GenRSA.hpp"
#include "AES_lib/AES_utils.hpp"

using namespace std;

class Client {
public:
	Client(const string& host, int port) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd == -1) {
			perror("socket");
			return;
		}

		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

		if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == -1) {
			perror("connect");
			close(sockfd);
			sockfd = -1;
		}

		load_rsa_from_file();
	}

	~Client() {
		if (sockfd != -1) {
			close(sockfd);
		}
	}

	void send_message(const string& message) {
		uint32_t len = htonl(message.size());
		write(sockfd, &len, sizeof(len));
		write(sockfd, message.c_str(), message.size());

		// Read reply
		uint32_t reply_len;
		read(sockfd, &reply_len, sizeof(reply_len));
		reply_len = ntohl(reply_len);

		string reply(reply_len, 0);
		read(sockfd, &reply[0], reply_len);
		cout << "Client received: " << reply << "\n";
	}

	void request_WUP() {
		// AES generate key
		// Should send iv and key together, append like: RSA_Enc(iv + key)
		// type: vector<unsigned char>
		AES_utils aesutil;
		aes_key = aesutil.generate_key();
		aes_iv = aesutil.generate_iv();
		vector<unsigned char> aes_message;
		copy(aes_iv.begin(), aes_iv.end(), back_inserter(aes_message));
		aes_message.insert(aes_message.end(), aes_key.begin(), aes_key.end());

		mpz_t aes_key_mpz;
		mpz_init(aes_key_mpz);
		aesutil.vec2mpz(aes_key_mpz, aes_key);
		cout << "-> Session AES Key: " << aes_key_mpz << endl;

		mpz_t aes_iv_mpz;
		mpz_init(aes_iv_mpz);
		aesutil.vec2mpz(aes_iv_mpz, aes_iv);
		cout << "-> Session AES IV: " << aes_iv_mpz << endl;

		mpz_t aes_message_mpz;
		mpz_init(aes_message_mpz);
		aesutil.vec2mpz(aes_message_mpz, aes_message);
		cout << "-> Session AES IV+Key: " << aes_message_mpz << endl;

		mpz_t aes_rsa_cipher;
		mpz_init(aes_rsa_cipher);
		encrypt_RSA(aes_rsa_cipher, aes_message_mpz, rsa_key);
		cout << "-> Session AES IV+Key RSA cipher: " << aes_rsa_cipher << endl;

		string wup_message = generate_wup_message();
		cout << "-> WUP request: " << wup_message << endl;
		mpz_t aes_encrypted_wup, wup_mpz;
		mpz_inits(aes_encrypted_wup, wup_mpz, NULL);
		mpz_set_str(wup_mpz, wup_message.c_str(), 10);

		vector<unsigned char> aes_encrypted_wup_vec = aesutil.encrypt_string(wup_message, aes_key, aes_iv);
		cout << "BEFORE SEND:: WUP hex = " << vec2hex(aes_encrypted_wup_vec) << endl;
		aesutil.vec2mpz(aes_encrypted_wup, aes_encrypted_wup_vec);
		cout << "-> WUP request encrypted: " << aes_encrypted_wup << endl;
		cout << "-> WUP request try decrypt: " << aesutil.decrypt_from_mpz(aes_encrypted_wup, aes_key, aes_iv) << endl;
		cout << "-> WUP request raw mpz: " << wup_mpz << endl;

		send_mpz_wup(aes_rsa_cipher, aes_encrypted_wup);

		stringstream ss_aes, ss_wup, ss_cwup;
		ss_aes << "###" << endl;
		ss_aes << "AES_Key:" << vec2hex(aes_key) << endl;
		ss_aes << "AES_IV: " << vec2hex(aes_iv) << endl;

		vector<unsigned char> wup_vec = vector<unsigned char>(wup_message.begin(), wup_message.end());
		ss_wup << "###" << endl;
		ss_wup << "WUP: " << vec2hex(wup_vec) << endl;

		ss_cwup << "###" << endl;
		ss_cwup << "WUP encrypted: " << vec2hex(aes_encrypted_wup_vec) << endl;

		fstream fout;
		fout.open("history/AES_Key.txt", ios::app | ios::out);
		fout << ss_aes.str();
		fout.close();

		fout.open("history/WUP_Request.txt", ios::app | ios::out);
		fout << ss_wup.str();
		fout.close();

		fout.open("history/AES_Encrypted_WUP.txt", ios::app | ios::out);
		fout << ss_cwup.str();
		fout.close();

		mpz_clears(aes_rsa_cipher, aes_encrypted_wup, wup_mpz, aes_message_mpz, aes_iv_mpz, NULL);
	}

	void send_mpz_wup(const mpz_t &data_aes, const mpz_t &data_wup) {
		AES_utils aesutil;
		vector<unsigned char> data_aes_vec, data_wup_vec;
		data_aes_vec = aesutil.mpz2vec(data_aes);
		data_wup_vec = aesutil.mpz2vec(data_wup);
		cout << "SEND:: WUP hex = " << vec2hex(data_wup_vec) << endl;
		// uint32_t aes_len = htonl(data_aes_vec.size());
		// uint32_t wup_len = htonl(data_wup_vec.size());
		uint32_t aes_len = data_aes_vec.size(), aes_len_send = htonl(aes_len);
		uint32_t wup_len = data_wup_vec.size(), wup_len_send = htonl(wup_len);
		uint32_t total_len = aes_len + wup_len, total_len_send = htonl(total_len);
		cout << aes_len << " " << wup_len << " " << total_len << endl;
		cout << data_aes_vec.size() << " " << data_wup_vec.size() << endl;

		if(send(sockfd, &total_len_send, sizeof(total_len_send), 0) != sizeof(total_len_send)){
			cerr << "Error: Unable to send total length" << endl;
			return;
		}
		if(send(sockfd, &aes_len_send, sizeof(aes_len_send), 0) != sizeof(aes_len_send)){
			cerr << "Error: Unable to send AES length" << endl;
			return;
		}
		if(send(sockfd, data_aes_vec.data(), data_aes_vec.size(), 0) != (ssize_t)data_aes_vec.size()){
			cerr << "Error: Unable to send AES data" << endl;
			return;
		}
		if(send(sockfd, data_wup_vec.data(), data_wup_vec.size(), 0) != (ssize_t)data_wup_vec.size()){
			cerr << "Error: Unable to send WUP data" << endl;
			return;
		}
	}

private:
	int sockfd = -1;
	RSAPublicKey rsa_key;

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

		mpz_set_str(rsa_key.N, str_n.c_str(), 10);
		mpz_set_str(rsa_key.key, str_e.c_str(), 10);
		cout << "RSA Moduler: " << rsa_key.N << endl;
		cout << "RSA public key: " << rsa_key.key << endl;
	}

	vector<unsigned char> aes_key, aes_iv;

	string getCurrentTime() const {
		time_t now = time(nullptr);
		char buf[32];
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
		return std::string(buf);
	}

	string get_local_ip() {
		struct ifaddrs *ifaddr, *ifa;
		string result = "127.0.0.1";
	    
		if (getifaddrs(&ifaddr) == -1) {
			return result;
		}
	    
		for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET)
				continue;
		
			string name(ifa->ifa_name);
			if (name.find("lo") != string::npos)
				continue;
		
			char ip[INET_ADDRSTRLEN];
			void* addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
			result = ip;
			break;
		}
	    
		freeifaddrs(ifaddr);
		return result;
	}

	string generate_wup_message() {
		string nonsense_str = "----------------";
		return nonsense_str + "WUP|" + get_local_ip() + "|" + getCurrentTime();
	}
};

#endif