#include <iostream>
#include <stdexcept>
#include "../header_files/ServerSecureConnection.h"
#include "../header_files/VirtualNetworkInterface.h"
#include "../header_files/VPNController.h"

int main()
{
	try
	{
		ServerSecureConnection secureConnection{ "172.235.54.87", 8080 };
		VirtualNetworkInterface networkInterface{ "10.8.0.1" };
		VPNController controller{secureConnection, networkInterface};
		controller.start();
		controller.singleThreadVPN();
		//controller.recvFromClient();
		//ServerSecureConnection.connect();
		//ServerSecureConnection.sslSendRecvTest();
        //ServerSecureConnection.start();

		//ServerSecureConnection.wintunReadTest();

		//VirtualNetworkInterface networkInterface{};

	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
