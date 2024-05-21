//
// HTTPSClient_with_Datafile_Encryption and Decryption.cpp
//
// $Id: //poco/1.7/Net/samples/httpget/src/httpget.cpp#1 $
//
// This sample demonstrates the HTTPSClientSession and the HTTPCredentials classes.
//
// Copyright (c) 2005-2012, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <stdio.h>
#include"rs232.h"


#include "Poco/Crypto/Crypto.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/CryptoStream.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/KeyConsoleHandler.h"
#include "Poco/Net/AcceptCertificateHandler.h"
#include "Poco/Net/ConsoleCertificateHandler.h"
#include "Poco/Exception.h"
#include "Poco/SharedPtr.h"
#include "Poco/Net/X509Certificate.h"
#include <Poco/Net/HTTPSClientSession.h>
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include <Poco/Net/HTTPCredentials.h>
#include "Poco/StreamCopier.h"
#include "Poco/NullStream.h"
#include "Poco/Path.h"
#include "Poco/URI.h"
#include "Poco/Exception.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <iostream>
#include <string>       // std::string
#include <iostream>     // std::cout
#include "sstream"     // std::istringstream
#include "fstream"
#include "Poco/StreamCopier.h"
#include "Poco/FileStream.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/SocketStream.h"

using namespace Poco;
using namespace Poco::Net;
using Poco::Net::HTTPSClientSession;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPMessage;
using Poco::StreamCopier;
using Poco::Path;
using Poco::URI;
using Poco::Exception;

void decrypt(void);

char q[100]="Hello Client";
char z[80];


	int cport_nr=4,i=0,n=0,        /* /dev/ttyS0 (COM1 on windows) */
	bdrate=115200;       /* 115200 baud */
  unsigned char read_buf='NULL',Copy_read_buf, Response[20];





bool doRequest(Poco::Net::HTTPSClientSession& session, Poco::Net::HTTPRequest& request, Poco::Net::HTTPResponse& response)
{



	std::cout << " "<< std::endl;
	std::cout << " "<< std::endl;

	std::ofstream myfile;
	myfile.open ("input");
	myfile << z << std::endl;
	myfile.close();

		    Poco::Crypto::CipherFactory& factory = Poco::Crypto::CipherFactory::defaultFactory();
		    Poco::Crypto::Cipher* pCipher = factory.createCipher(Poco::Crypto::RSAKey("Publik.pem","",""));  /* Here v r encrypting the message with publickey "anyCertpub.pem". This file is extracted from server certificate file anyCert.pem through openssl */

		    Poco::Crypto::CryptoTransform *pEncryptor = NULL;

		        pEncryptor = pCipher->createEncryptor();
		        Poco::FileOutputStream sink("encrypted");
		        Poco::Crypto::CryptoOutputStream encryptor(sink, pEncryptor);
		        Poco::FileInputStream source("input");
		        Poco::StreamCopier::copyStream(source, encryptor);
		        // Always close output streams to flush all internal buffers
		        encryptor.close();
		        sink.close();

		        std::ifstream in("encrypted", std::ios::binary|std::ios::in);
		        	    if(!in.is_open())
		        	       return false;
		        	    std::string data;
		        	    data.append(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
		        	    in.close();
		  		        request.setContentLength(data.length());

		  		     	session.sendRequest(request)<<data<<std::endl;
		  		     	data.clear();

		  		     	std::cout << " "<< std::endl;
		  		     	std::cout << " "<< std::endl;

		  		     	std::cout << "\nMessage from Client:\n" << z << std::endl;

		  		     	std::cout << " "<< std::endl;
		  		     	std::cout << " "<< std::endl;



		        //decrypt();

		        std::ofstream ofs;
		        ofs.open("encrypted", std::ofstream::out|std::ofstream::trunc);
		        ofs.close();

		        std::ofstream ofs1;
		        ofs1.open("input", std::ofstream::out|std::ofstream::trunc);
		        ofs1.close();

		        std::remove("input");
		        std::remove("encrypted");


	std::istream& rs = session.receiveResponse(response);




	if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
	{
		int retbyte=0;
		retbyte=StreamCopier::copyStream(rs, std::cout);

		if(retbyte!=0)
		Copy_read_buf=read_buf;

		std::cout << " "<< std::endl;
		std::cout << " "<< std::endl;
        return true;
	}
	else
	{
		Poco::NullOutputStream null;
		StreamCopier::copyStream(rs, null);

		return false;
	}
}



/*This decrypt() is for cross verification only. Here we are decrypting the encrypted file using Server private key "any.pem" inorder to check whether message is correctly encrypted or not */
/*
void decrypt()
{

	    Poco::Crypto::CipherFactory &factory = Poco::Crypto::CipherFactory::defaultFactory();
	    Poco::Crypto::Cipher* pCipher = factory.createCipher(Poco::Crypto::RSAKey("", "any.pem", "secret"),RSA_PADDING_PKCS1);

	    std::ifstream in("encrypted", std::ios::binary|std::ios::in);
	    if(!in.is_open())
	        return;
	    std::string data;
	    data.append(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
	    in.close();
	    const std::string decrypted_string(pCipher->decryptString(data));
	    std::cout << "\nMessage to be Encrypted:\n" << decrypted_string << std::endl;

}

*/

int main()
{
	while(1)
	{

int count=2;
char *input="http://159.99.184.156:80";

	if (count != 2)
	{
		Path p(input[0]);
		std::cout << "usage: " << p.getBaseName() << " <uri>" << std::endl;
		//std::cout<<argv[1]<<std::endl;
		std::cout << "       fetches the resource identified by <uri> and print it to the standard output" << std::endl;
		return 1;
	}

	try
	{
		URI uri(input);
		std::string path(uri.getPathAndQuery());
		if (path.empty()) path = "/";


///// UART




		if(RS232_OpenComport(cport_nr, bdrate))
			{
				printf("Can not open comport\n");
				return(0);
			}


			printf("Receiving data\n");

		do
		{

			//sleep(2);  /* sleep for 100 milliSeconds */
	     	//while(n==0)  /*Donot use this while loop... read_buf will NOT be updated */

			n=RS232_PollComport(cport_nr, &read_buf, 1);
			printf("Received : %c  %c\n\n",read_buf, Copy_read_buf);


		if(Copy_read_buf!=read_buf)

		{
			if(n>0)
			{

				printf("Received : %c\n\n",read_buf);

				   	if(read_buf=='1')
					   {
				   		 strcpy(z,"!!!!...REMOTE SYNC TROUBLE...!!!!");
							break;
					   }

						else if(read_buf=='0')
						{
							strcpy(z,"!!!!...REMOTE SYNC TROUBLE CLEARED..!!!!");
							break;

						}

						//sleep(1);

			 }

			//usleep(100000);  /* sleep for 100 milliSeconds */

		}


	        }while(1);





///// UART




        std::string username;
        std::string password;
        Poco::Net::HTTPCredentials::extractCredentials(uri, username, password);
        Poco::Net::HTTPCredentials credentials(username, password);
        SharedPtr<PrivateKeyPassphraseHandler> pConsoleHandler = new KeyConsoleHandler(false);
        SharedPtr<InvalidCertificateHandler> pInvalidCertHandler = new ConsoleCertificateHandler(false);
         Context::Ptr pContext = new Context(Context::CLIENT_USE, "", "", "rootcert.pem", Context::VERIFY_STRICT, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
        SSLManager::instance().initializeClient(pConsoleHandler, pInvalidCertHandler, pContext);
		HTTPSClientSession session(uri.getHost(), uri.getPort(), pContext);
		HTTPRequest request(HTTPRequest::HTTP_POST, path, HTTPMessage::HTTP_1_1);
		HTTPResponse response;
		if (!doRequest(session, request, response))
		{
            credentials.authenticate(request, response);
			if (!doRequest(session, request, response))
			{
				std::cerr << "Invalid username or password" << std::endl;
				return 1;
			}
		}
	}

	catch (Exception& exc)
	{
		std::cerr << exc.displayText() << std::endl;
		std::cout << " "<< std::endl;
		std::cout << " "<< std::endl;
		return 1;
	}

	}
	return 0;


}



