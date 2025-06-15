#include <iostream>
#include "server.hpp"

int main(int argc, char *argv[]) {
	Server sv(8081);
	sv.start();
}