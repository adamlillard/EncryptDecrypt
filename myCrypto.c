/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By: 
     1- Adam Lillard
     
Submitted on: 9/16
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}
//-----------------------------------------------------------------------------

static unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] , 
                       ciphertext[ CIPHER_LEN_MAX    ] ,
                       decryptext[ DECRYPTED_LEN_MAX ] ;

// above arrays being static to resolve runtime stack size issue. 
// However, that makes the code non-reentrant for multithreaded application
//-----------------------------------------------------------------------------


int encryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int status;
    unsigned len = 0, encryptedLen = 0;
    uint8_t plain = plaintext;
    uint8_t cipher = ciphertext;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();   
    if (!ctx)   
        handleErrors("encrypt: failed to creat CTX");
   
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
   
    int bytes;
    while((bytes = read(fd_in, plaintext, 1008)) != 0)
    status = EVP_EncryptUpdate(ctx, cipher, &len, plain, bytes);
    if (status != 1){
        handleErrors("encrypt: failed to EncryptUpdate");
        write(fd_out, cipher, len);
        encryptedLen += len;
    }
    cipher += len;
   
    status = EVP_EncryptFinal_ex(ctx, cipher, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; 
    EVP_CIPHER_CTX_free(ctx);
    
    return encryptedLen;

}

int decryptFile(int fd_in, int fd_out, const uint8_t *key, const uint8_t *iv)
{
    int status;
    unsigned len = 0, decryptedLen = 0;
    uint8_t plain = plaintext;
    uint8_t cipher = ciphertext;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();   
    if (!ctx)   
        handleErrors("encrypt: failed to creat CTX");
   
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
   
        handleErrors("encrypt: failed to DecryptInit_ex");
   
    int bytes;
    while((bytes = read(fd_in, cipher, ciphertext)) != 0)
    status = EVP_DecryptUpdate(ctx, plain, &len, cipher, bytes);
    if (status != 1){
        handleErrors("encrypt: failed to DecryptUpdate");
        write(fd_out, plain, len);
        decryptedLen += len;
    }
    plain += len;
   
    status = EVP_DecryptFinal_ex(ctx, plain, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    decryptedLen += len; 
    EVP_CIPHER_CTX_free(ctx);
    
    return decryptedLen;

}

