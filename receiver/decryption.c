#include <stdlib.h>
#include <string.h>
#include "sodium.h"
#include "sodium/crypto_box.h"
#include "sodium/crypto_sign.h"

#define MESSAGE_LEN 32
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

int main(){
 unsigned char publickey1S[crypto_sign_PUBLICKEYBYTES];
 unsigned char publickey2S[crypto_box_PUBLICKEYBYTES];
 unsigned char secretkey1R[crypto_box_SECRETKEYBYTES];
 unsigned char unsigned_message[CIPHERTEXT_LEN];
 unsigned long long unsigned_message_len;
 unsigned char signed_message[crypto_sign_BYTES + CIPHERTEXT_LEN];
 unsigned long long signed_message_len;
 unsigned char decrypted[MESSAGE_LEN];
 unsigned char NONCE[crypto_box_NONCEBYTES];
 
  //initializes any use of the functions in the sodium library
  sodium_init();

  FILE* file_val= fopen("file_val_pks.bin", "rb");
  fread(publickey1S, sizeof(publickey1S), 1, file_val);

  FILE* file_dec= fopen("file_dec_skr.bin", "rb");
  fread(secretkey1R, sizeof(secretkey1R), 1, file_dec);

  FILE* file_enc= fopen("file_enc_pks.bin", "rb");
  fread(publickey2S, sizeof(publickey2S), 1, file_enc);

  FILE* sign_file= fopen("signed_file.bin", "rb");
  fread(signed_message, sizeof(signed_message), 1, sign_file);
  
  FILE* nonce= fopen("nonce.bin", "rb");
  fread(NONCE,crypto_box_NONCEBYTES , 1, nonce);

  //initializing the signed_message_len
  signed_message_len= crypto_sign_BYTES + CIPHERTEXT_LEN;

  
 /* Pre condition- appropriate space needs to be allocated for unsigned message
    Post condition- validates the signature of the signed message and using 
    the sender's public key and stores the encripted message in 
    unsigned_message.
 */
     
  int j;
  j= crypto_sign_open(unsigned_message,&unsigned_message_len,signed_message,signed_message_len,publickey1S);
  printf("%d\n", j);
  
 /* Pre condition- appropriate space needs to be allocated for decreypted 
    message
    Post condition- decrypts the encrypted message and stores it in decrypted.
 */
  int i;
  i= crypto_box_open_easy(decrypted,unsigned_message,unsigned_message_len,NONCE, publickey2S,secretkey1R);
  printf("%d\n", i);

  FILE* msg_val= fopen("validation.txt", "w");
  fwrite(decrypted, MESSAGE_LEN, 1, msg_val);


  fclose(file_val);
  fclose(file_dec);
  fclose(file_enc);
  fclose(sign_file);
  fclose(nonce);
  return 0;
}
  
