//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>
#include <openssl/rand.h>   // Random numbers

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);
	

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	cout << endl;
	printf("2. Waiting for client to connect and send challenge...");

	unsigned char* ena = (unsigned char *) malloc(500);
	unsigned char* buff = (unsigned char *) malloc(500);
    BIO * rsaprivin = BIO_new_file("rsaprivatekey.pem","r");
    RSA * rsapriv = PEM_read_bio_RSAPrivateKey(rsaprivin,NULL,0,NULL);
    int len = RSA_size(rsapriv);
	int leng = len-12;
	int osize = 16;
	
    SSL_read(ssl,ena,len);
    int dsize;


    dsize = RSA_private_decrypt(len, (unsigned char *) ena, buff, rsapriv, RSA_PKCS1_PADDING);
   
    
    
	printf("DONE.\n");
	cout << "Challenge : " << endl << buff2hex((const unsigned char*)ena,len) << endl;

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	cout << endl;
	printf("3. Generating SHA1 hash...");

	unsigned char obuff[osize];
	SHA1(buff,dsize,obuff);
	
	printf("SUCCESS.\n");
	cout << "SHA1 hash: " << endl <<buff2hex((const unsigned char*)obuff,osize)<< " (" << osize << " Bytes) " << endl;

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	cout << endl;
	printf("4. Signing the key...");
	unsigned char sendh[len];
    int siglen=RSA_private_encrypt(leng,obuff,sendh, rsapriv, RSA_PKCS1_PADDING);

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Encrypted Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)sendh, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	cout << endl;
	printf("5. Sending signature to client for authentication...");
	
	SSL_write(ssl,sendh,siglen);
	BIO_flush(server);
	//cout << endl << buff2hex((const unsigned char*)ena,len)<< " " << endl;	

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	cout << endl;
	printf("6. Receiving file request from client...");
    
    char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
    SSL_read(ssl,file,BUFFER_SIZE);
    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\")\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	cout << endl;
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	BIO_flush(server);
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);
	
    int bytesSent=0;
    char fbuff[leng];
    char efbuff[len];
    memset(fbuff,0,leng);
    //string fname = file;
    BIO * fil = BIO_new_file(file,"r");
	if(fil == 0)
	{
	 cout << endl << "Not found... Exiting" << endl;
	 

	SSL_shutdown(ssl);
	BIO_free_all(server);
	return 0;
		
	}
	int actualRead=0;
	int actualWritten=0;
	int actualenc = 0;

	while((actualRead = BIO_read(fil, fbuff, leng-1)) >= 1)
	{
		actualenc = RSA_private_encrypt(actualRead,(const unsigned char*)fbuff,(unsigned char*)efbuff, rsapriv, RSA_PKCS1_PADDING);
		bytesSent +=SSL_write(ssl,efbuff,actualenc);
		memset(fbuff,0,leng);
		memset(efbuff,0,len);
	}

	
    //char fbuff[1024];
    //BIO * fil = BIO_new_file(file,"r");
    //int flen = BIO_read(fil,fbuff,sizeof(fbuff));
    //printf(fbuff);
    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	cout << endl;
	printf("8. Closing connection...");

	 SSL_shutdown(ssl);
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}


