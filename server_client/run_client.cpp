#include <iostream>
#include "client.hpp"
using namespace std;

int main(int argc, char *argv[]) {
        while(true) {
		cout << "> ";
		string command;
		getline(cin, command);
		if(command == "exit") {
			Client client("127.0.0.1", 8081);
			client.send_message("EXIT");
			break;
		}
		else {
			Client client("127.0.0.1", 8081);
			// client.send_message(command);
			cout << command << endl;
			client.request_WUP();
		}
	}
}