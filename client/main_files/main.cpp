#include <iostream>
#include <stdexcept>
#include "..\header_files\ClientSecureConnection.h"
#include "..\header_files\VirtualNetworkInterface.h"
#include "..\header_files\VPNController.h"

int main()
{
	try
	{
		ClientSecureConnection clientSecureConnection{"127.0.0.1", 8080 };
		VirtualNetworkInterface virtualNetworkInterface{};
		VPNController controller{clientSecureConnection, virtualNetworkInterface};
		controller.start();
		controller.readFromWintun();
	}
	catch (const std::runtime_error& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
