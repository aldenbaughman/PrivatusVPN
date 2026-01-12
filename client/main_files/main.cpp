#include <iostream>
#include <stdexcept>
#include <csignal>
#include "..\header_files\ClientSecureConnection.h"
#include "..\header_files\VirtualNetworkInterface.h"
#include "..\header_files\VPNController.h"



int main()
{
	try
	{
		ClientSecureConnection clientSecureConnection{"172.235.54.87", 8080 };
		
		VirtualNetworkInterface virtualNetworkInterface{"172.235.54.87", "10.8.0.1"};
		//virtualNetworkInterface.start();
		//virtualNetworkInterface.ping_test();
		//virtualNetworkInterface.start();
		//virtualNetworkInterface.ping_test();
		VPNController controller{clientSecureConnection, virtualNetworkInterface};
		//controller.tls_test();
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
