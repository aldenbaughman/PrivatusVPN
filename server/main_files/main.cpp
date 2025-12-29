#include <iostream>
#include <stdexcept>
#include "../header_files/ServerSecureConnection.h"

int main()
{
	try
	{
		ServerSecureConnection ServerSecureConnection{ "127.0.0.1", 8080 };

        ServerSecureConnection.start();

	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
