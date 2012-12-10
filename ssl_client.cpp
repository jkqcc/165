//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <iostream>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>   // Random numbers

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	size_t flen = strlen(filename);
	cout << flen << endl;
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);
	

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	cout << endl;
	printf("2.  Sending challenge to the server...");

	unsigned char * a =  (unsigned char *) malloc(500);
	unsigned char* ena = (unsigned char *) malloc(500);
    int bsize;
	int osize = 16;
	
    BIO * rsapubin = BIO_new_file("rsapublickey.pem","r");
    RSA * rsapub = PEM_read_bio_RSA_PUBKEY(rsapubin,NULL,0,NULL);
    
    int leng = RSA_size(rsapub)-12;
    int len = leng + 12;
	if(!RAND_bytes(a,leng))
	{
		exit(EXIT_FAILURE);
	}    

    bsize = RSA_public_encrypt(leng, (unsigned char *) a, ena, rsapub, RSA_PKCS1_PADDING);
	
	SSL_write(ssl,ena,bsize);
	

	int SSL_shutdown(SSL *ssl);    
    printf("SUCCESS.\n");
    cout << "PlainText Challenge: " << endl << buff2hex((const unsigned char*)a,leng) << endl;
    cout << "Encrypted Challenge: " << endl << buff2hex((const unsigned char*)ena,bsize) << endl << endl;
	
    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	cout << endl;
	printf("3a. Receiving signed key from server...");

    unsigned char* recv = new unsigned char[len];
    unsigned char* reca = new unsigned char[leng];
	
    SSL_read(ssl,recv,len);
    int dsize;
 


    dsize = RSA_public_decrypt(len,recv, reca, rsapub, RSA_PKCS1_PADDING);
    printf("RECEIVED.\n");
	printf("    (Plaintext Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)reca, dsize).c_str(), dsize);
	cout << "Plaintext Signature: " << endl << buff2hex((const unsigned char*)reca, dsize) << " (" << dsize << ") bytes." << endl;
    //-------------------------------------------------------------------------
	// 3a1. HASH challenge
	cout << endl;
	printf("3a1. Generating SHA1 hash...");

	unsigned char obuff[osize];
	SHA1(a,leng,obuff);
	
	printf("SUCCESS.\n");
	cout << "SHA1 hash: " << buff2hex((const unsigned char*)obuff,osize)<< " (" << osize<< " Bytes) " << endl;	


    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	cout << endl;
	printf("3b. Authenticating key...");
	
	string generated_key=buff2hex((const unsigned char*)obuff,osize);
	string decrypted_key=buff2hex((const unsigned char*)reca,osize);
    if(generated_key == decrypted_key){
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());
	}
	else
	{
		printf("NOT AUTHENTICATED\n");
	}
    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	cout << endl;
	printf("4.  Sending file request to server...");

	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write
	
	SSL_write(ssl,filename,flen);
	BIO_flush(client);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	cout << endl;
	printf("5.  Receiving response from server...");

    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free
	BIO_flush(client);
	int bytesRecieved=0;
    char fbuff[leng];
    char dfbuff[leng-1];
    memset(fbuff,0,leng);
    BIO * fil = BIO_new_file("output.txt","w");

	int actualWritten=0;
	int actualdec = 0;

	while((actualWritten = SSL_read(ssl,fbuff,len)) >= 1)
	{
		actualdec = RSA_public_decrypt(actualWritten,(const unsigned char*)fbuff, (unsigned char*)dfbuff, rsapub, RSA_PKCS1_PADDING);
		bytesRecieved +=BIO_write(fil,dfbuff,actualdec);
		memset(fbuff,0,leng);
		memset(dfbuff,0,leng-1);
	}
	if(bytesRecieved ==0)
	{
		cout << endl << "Yea.... Nothing there..... Exiting " << endl;
		SSL_shutdown(ssl);
		SSL_CTX_free(ctx);
		SSL_free(ssl);
		return 0;
	}
		


	printf("FILE RECEIVED.\n");
	printf("    (Bytes received: %d)\n", bytesRecieved);

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
