#include <stdlib.h>
#include "sodium.h"
#include "sodium/crypto_box.h"
#include "sodium/crypto_sign.h"


int main(){
  //Generating keypair for encrypting and decrypting a message
  unsigned char publickey1[crypto_box_PUBLICKEYBYTES];
  unsigned char secretkey1[crypto_box_SECRETKEYBYTES];

  //Generating the keypair for signing and validating a signature
  unsigned char publickey2[crypto_sign_PUBLICKEYBYTES];
  unsigned char secretkey2[crypto_sign_SECRETKEYBYTES];

  //initializes any use of the functions in the sodium library
 sodium_init();

 /* Pre condition- appropriate space needs to be allocated for public key and 
    secret key.
    Post condition- generates for encrypting and decrypting a messagkeypair in 
    the allocated space.
 */
 crypto_box_keypair(publickey1,secretkey1);
  FILE * file_enc= fopen ("file_enc_pkr.bin", "wb");
  if (file_enc != NULL) {
        fwrite (publickey1, sizeof (publickey1), 1, file_enc);
        fclose (file_enc);
    }
   FILE * file_dec= fopen ("file_dec_skr.bin", "wb");
  if (file_dec != NULL) {
        fwrite (secretkey1, sizeof (secretkey1), 1, file_dec);
        fclose (file_dec);
    }
  
 /* Pre condition- appropriate space needs to be allocated for public key and 
    secret key.
    Post condition- generates keypair for signing and validating a signature in
    the allocated space.  */  
  crypto_sign_keypair(publickey2,secretkey2);
  FILE * file_cons= fopen ("file_cons_skr.bin", "wb");
  if (file_cons != NULL) {
        fwrite (secretkey2, sizeof (secretkey2), 1, file_cons);
        fclose (file_cons);
    }
 FILE * file_val= fopen ("file_val_pkr.bin", "wb");
  if (file_val != NULL) {
        fwrite (publickey2, sizeof (publickey2), 1, file_val);
        fclose (file_val);
    }

 return 0;
}


