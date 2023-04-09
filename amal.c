#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    uint8_t key[SYMMETRIC_KEY_LEN] , iv[INITVECTOR_LEN];
    unsigned key_len = 32;  //i.e. 256 bits
    unsigned iv_len = 16;
    int fd_ctrl, fd_data;
    
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    if( argc < 3 )
    {
        printf("Basim is missing command-line arguments. Usage: %s <ctrlFD> <dataFD>\n" , argv[0]);
        exit(-1) ;
    }
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;
    FILE *log = fopen("amal/logAmal.txt" , "w" );
    if ( ! log )
        { fprintf( stderr , "This is Amal. Could not create log file\n"); exit(-1)
; }
    fprintf( log , "This is AMal. Will read encrypted data from FD %d\n" , fd_data
);
                   
    // Get the session symmetric key
    int fd_key = open("amal/key.bin" , O_RDONLY )  ;
    if ( fd_key == -1 )
        { fprintf( log , "\nCould not open Amals's key.bin\n"); exit(-1) ;}
    read ( fd_key , key, key_len ) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, (const char *) key, key_len );
    close( fd_key ) ;
    // Get the session Initial Vector 
    int fd_iv = open( "amal/iv.bin" , O_RDONLY )  ;
    if ( fd_iv == -1 )
        { fprintf( log , "\nCould not open Basim's iv.bin\n"); exit(-1) ;}
    read ( fd_iv , iv, iv_len ) ;
    fprintf( log, "\nUsing this symmetric key of length %d bytes\n" , key_len );
    BIO_dump_fp ( log, (const char *) iv, iv_len );
    close( fd_iv ) ;
    char* fd_decr = open(".//bunny.mp4", O_RDONLY);
    if( fd_decr == -1 )
        { fprintf( log , "\nCould not open '%s'\n" , fd_decr ); exit(-1) ; }
   
    fflush( log ) ;
    encryptFile(fd_decr, fd_data, key, iv);
    fclose(fd_decr);
    ERR_free_strings();
    return 0;
}