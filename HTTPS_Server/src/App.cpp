//
// HTTPServer.cpp
//
// $Id: //poco/1.7/Net/samples/HTTPTimeServer/src/HTTPTimeServer.cpp#1 $
//
// This sample demonstrates the HTTPServer and related classes.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//



#include "Poco/Net/SSLManager.h"
#include "Poco/Net/KeyConsoleHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/ConsoleCertificateHandler.h"
#include "Poco/Exception.h"
#include "Poco/SharedPtr.h"

#include "Poco/Crypto/Crypto.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CryptoStream.h"

#include <iostream>
#include <string>       // std::string
#include <iostream>     // std::cout
#include "sstream"     // std::istringstream
#include "fstream"

#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/SecureStreamSocket.h"
#include "Poco/Net/SecureServerSocket.h"
#include "Poco/Net/X509Certificate.h"
#include "Poco/Net/HTTPServerRequestImpl.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Timestamp.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/Exception.h"
#include "Poco/ThreadPool.h"
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/KeyConsoleHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/ConsoleCertificateHandler.h"

#include <iostream>


#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/Socket.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Net/SocketStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Timespan.h"
#include "Poco/FileStream.h"

using namespace Poco;
using namespace Poco::Net;



using Poco::Net::SecureServerSocket;
using Poco::Net::SecureStreamSocket;
using Poco::Net::ServerSocket;
using Poco::Net::HTTPRequestHandler;
using Poco::Net::HTTPRequestHandlerFactory;
using Poco::Net::HTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerRequestImpl;
using Poco::Net::X509Certificate;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Timestamp;
using Poco::DateTimeFormatter;
using Poco::DateTimeFormat;
using Poco::SharedPtr;
using Poco::ThreadPool;
using Poco::Util::ServerApplication;
using Poco::Util::Application;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;
using Poco::Net::SSLManager;

using Poco::Net::Context;
using Poco::Net::KeyConsoleHandler;
using Poco::Net::PrivateKeyPassphraseHandler;
using Poco::Net::InvalidCertificateHandler;
using Poco::Net::AcceptCertificateHandler;

char a[30]="!!!! Hello from Server !!!!";




class TimeRequestHandler: public HTTPRequestHandler
	/// Return a HTML document with the current date and time.
{
public:
	TimeRequestHandler(const std::string& format):
		_format(format)
	{
	}

	void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response)
	{
		std::istream& i = request.stream();
		unsigned int len = request.getContentLength();
		char* buffer = new char[len];
		i.read(buffer, len);



		std::cout << "\nEncrypted data: \n"<<buffer<<std::endl;


		std::cout << " "<< std::endl;
		std::cout << " "<< std::endl;

		Poco::Crypto::CipherFactory &factory = Poco::Crypto::CipherFactory::defaultFactory();
		//Poco::Crypto::Cipher* pCipher = factory.createCipher(Poco::Crypto::RSAKey("", "server.key", "aravind"),RSA_PADDING_PKCS1);
		Poco::Crypto::Cipher* pCipher = factory.createCipher(Poco::Crypto::RSAKey("", "any.pem", "secret"),RSA_PADDING_PKCS1);
		 const std::string decrypted_string(pCipher->decryptString(buffer));
		 std::cout << "\nDecrypted string: \n" << decrypted_string<<std::endl;
		 //delete buffer;
		buffer=NULL;
		std::remove(buffer);

		std::cout << " "<< std::endl;
		std::cout << " "<< std::endl;

		Application& app = Application::instance();

		app.logger().information("Request from " + request.clientAddress().toString());   //Uncomment this whwnever v need to display Client IP address

		SecureStreamSocket socket = static_cast<HTTPServerRequestImpl&>(request).socket();
		if (socket.havePeerCertificate())
		{
			X509Certificate cert = socket.peerCertificate();

			app.logger().information("Client certificate: " + cert.subjectName());

		}
		else
		{

		app.logger().information("No client certificate available.");      //Uncomment this whwnever v need to display Client Certificate

		}
		std::cout << " "<< std::endl;
		std::cout << " "<< std::endl;
		std::ostream& ostr = response.send();
		ostr << a;

}

private:
	std::string _format;
};


class TimeRequestHandlerFactory: public HTTPRequestHandlerFactory
{
public:
	TimeRequestHandlerFactory(const std::string& format):
		_format(format)
	{
	}

	HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request)
	{
		if (request.getURI() == "/")
			return new TimeRequestHandler(_format);
		else
			return 0;
	}

private:
	std::string _format;
};





class HTTPSTimeServer: public Poco::Util::ServerApplication
	/// The main application class.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the HTTPTimeServer executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (HTTPTimeServer.properties),
	/// copy the file to the directory where the HTTPTimeServer executable
	/// resides. If you start the debug version of the HTTPTimeServer
	/// (HTTPTimeServerd[.exe]), you must also create a copy of the configuration
	/// file named HTTPTimeServerd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/time string sent back to the client.
	///
	/// To test the TimeServer you can use any web browser (https://localhost:9980/).
{
public:
	HTTPSTimeServer(): _helpRequested(false)
	{
	}

	~HTTPSTimeServer()
	{
	}

protected:
	void initialize(Application& self)
	{
		loadConfiguration(); // load default configuration files, if present
		ServerApplication::initialize(self);
	}

	void uninitialize()
	{
		ServerApplication::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		ServerApplication::defineOptions(options);

		options.addOption(
			Option("help", "h", "display help information on command line arguments")
				.required(false)
				.repeatable(false));
	}

	void handleOption(const std::string& name, const std::string& value)
	{
		ServerApplication::handleOption(name, value);

		if (name == "help")
			_helpRequested = true;
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("A web server that serves the current date and time.");
		helpFormatter.format(std::cout);
	}

	int main(const std::vector<std::string>& args)
	{
		if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			// get parameters from configuration file
			unsigned short port = (unsigned short) config().getInt("HTTPTimeServer.port",80);
			std::string format(config().getString("HTTPTimeServer.format", DateTimeFormat::SORTABLE_FORMAT));
			int maxQueued  = config().getInt("HTTPTimeServer.maxQueued", 100);
		    int maxThreads = config().getInt("HTTPTimeServer.maxThreads", 16);
			ThreadPool::defaultPool().addCapacity(maxThreads);

			HTTPServerParams* pParams = new HTTPServerParams;
			pParams->setMaxQueued(maxQueued);
			pParams->setMaxThreads(maxThreads);
			SharedPtr<PrivateKeyPassphraseHandler> pConsoleHandler = new KeyConsoleHandler(false);
			SharedPtr<InvalidCertificateHandler> pInvalidCertHandler = new ConsoleCertificateHandler(false);
			//Context::Ptr pContext = new Context(Context::SERVER_USE, "server.key", "server.crt", "", Context::VERIFY_NONE, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
			Context::Ptr pContext = new Context(Context::SERVER_USE, "any.pem", "anyCert.pem", "rootcert.pem", Context::VERIFY_NONE, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
			SSLManager::instance().initializeServer(pConsoleHandler, pInvalidCertHandler, pContext);

			const char* ipaddr = "159.99.184.156";
			Poco::Net::SocketAddress sa(ipaddr,80);

			SecureServerSocket svs(sa,64,pContext);

			// set-up a HTTPServer instance
			HTTPServer srv(new TimeRequestHandlerFactory(format), svs, pParams);

			// start the HTTPServer
			srv.start();
			// wait for CTRL-C or kill
			waitForTerminationRequest();
			// Stop the HTTPServer
			srv.stop();
		}
		return Application::EXIT_OK;
	}

private:
	bool _helpRequested;
};


int main(int argc, char** argv)
{
	HTTPSTimeServer app;

	return app.run(argc, argv);
}
