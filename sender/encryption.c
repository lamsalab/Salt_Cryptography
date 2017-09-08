#include <stdlib.h>
#include "sodium.h"
#include "sodium/crypto_box.h"
#include "sodium/crypto_sign.h"

#define MESSAGE_LEN 32
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

int main(){
   unsigned char publickey1R[crypto_box_PUBLICKEYBYTES];
   unsigned char secretkey1S[crypto_box_SECRETKEYBYTES];
   unsigned char secretkey2S[crypto_sign_SECRETKEYBYTES];
   unsigned char MESSAGE[MESSAGE_LEN];
   unsigned char nonce[crypto_box_NONCEBYTES];
   unsigned char signed_message[crypto_sign_BYTES + CIPHERTEXT_LEN];
   unsigned long long signed_message_len;
   unsigned char ciphertext[CIPHERTEXT_LEN];
 
  //initializes any use of the functions in the sodium library
  sodium_init();
  
  FILE* file_enc= fopen("file_enc_pkr.bin", "rb");
  fread(publickey1R, sizeof(publickey1R), 1, file_enc);

  FILE* file_dec= fopen("file_dec_sks.bin", "rb");
  fread(secretkey1S, sizeof(secretkey1S), 1, file_dec);

  
 /* Pre condition- appropriate space needs to be allocated for nonce
    Post condition- generates a nonce and stores in the allocated space
 */
  randombytes_buf(nonce, sizeof(nonce));
  
  FILE* nonce_file= fopen("nonce.bin", "wb");
  if (nonce_file != NULL) {
  fwrite(nonce, crypto_box_NONCEBYTES, 1, nonce_file);
  }

  FILE * message = fopen("message.txt", "rb");
  fread(MESSAGE, sizeof (MESSAGE) , 1, message);

  FILE* file_sign= fopen("file_cons_sks.bin", "rb");
  fread(secretkey2S, sizeof(secretkey2S), 1, file_sign);

 /* Pre condition- appropriate space needs to be allocated for message to be read
    and the encrypted message               
    Post condition- encrypts the message using sender's secret key and receiver's public key
    and a nonce into ciphertext.
 */ 
  int j= crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, publickey1R, secretkey1S);
   printf("%d\n ", j);

 
 /* Pre condition- appropriate space needs to be allocated for signed_message
    Post condition- signs the encrypted message using the sender's secret key
    and stores it in signed_message
 */   
  int i= crypto_sign(signed_message, &signed_message_len, ciphertext,CIPHERTEXT_LEN, secretkey2S);
  printf("%d\n ", i);

   FILE * signed_file = fopen("signed_file.bin", "wb");
  if (signed_file != NULL){
    fwrite (signed_message, sizeof (signed_message), 1, signed_file);
  }

  fclose(signed_file);
  fclose(message);
  fclose(file_enc);
  fclose(file_dec);
  fclose(file_sign);
  fclose(nonce_file);
  
  return 0;
}

