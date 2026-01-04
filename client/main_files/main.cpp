#include <iostream>
#include <stdexcept>
#include "..\header_files\ClientSecureConnection.h"
#include "..\header_files\VirtualNetworkInterface.h"

int main()
{
	try
	{
		//ClientSecureConnection clientSecureConnection{"127.0.0.1", 8080 };

		//clientSecureConnection.secureConnect();

		VirtualNetworkInterface virtualNetworkInterface{};
		virtualNetworkInterface.ping_test();

	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
