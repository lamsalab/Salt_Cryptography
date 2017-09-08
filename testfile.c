#include <stdlib.h>
#include "sodium.h"
#include <string.h>
#include <stdio.h>
#include "sodium/crypto_box.h"
#include "sodium/crypto_sign.h"

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
unsigned char nonce[crypto_box_NONCEBYTES];
unsigned char ciphertext[CIPHERTEXT_LEN];
unsigned char decrypted[MESSAGE_LEN];

int main(){
   sodium_init();
   crypto_box_keypair(alice_publickey, alice_secretkey);
   crypto_box_keypair(bob_publickey, bob_secretkey);
   randombytes_buf(nonce, sizeof nonce);
   int j= crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce,
                    bob_publickey, alice_secretkey) ;
   printf("%d\n", j);

   

    int k= crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce,
                         alice_publickey, bob_secretkey);
   printf("%d\n", j); 
   int w= memcmp(MESSAGE, decrypted, 4);
   printf("%d\n", w);
           


    return 0;
}
