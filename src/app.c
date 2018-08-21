#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* #define ED25519_DLL */
#include "ed25519.h"

#include "ge.h"
#include "sc.h"

unsigned char seed[32], public_key[32], private_key[64], signature[64];
unsigned char other_public_key[32], other_private_key[64], shared_secret[32];
const unsigned char message[] = "TEST MESSAGE";

int main() {
/* create a random seed, and a key pair out of that seed */
if (ed25519_create_seed(seed)) {
    printf("error while generating seed\n");
    exit(1);
}
else {
    printf("SEED: ");
    for(int i=0;i<32; i++) {
        printf("%02x",seed[i]);
    } 
    printf("\n");
}
ed25519_create_keypair(public_key, private_key, seed);
printf("PUBLIC KEY: ");
for(int i=0;i<32; i++) {
    printf("%02x",public_key[i]);
} 
printf("\n");
printf("PRIVATE KEY: ");
for(int i=0;i<64; i++) {
    printf("%02x",private_key[i]);
} 
printf("\n");

/* create signature on the message with the key pair */
ed25519_sign(signature, message, strlen(message), public_key, private_key);

printf("SIGNATURE: ");
for(int i=0;i<64; i++) {
    printf("%02x", signature[i]);
} 
printf("\n");

/* verify the signature */
if (ed25519_verify(signature, message, strlen(message), public_key)) {
    printf("valid signature\n");
} else {
    printf("invalid signature\n");
}

/* create a dummy keypair to use for a key exchange, normally you'd only have
the public key and receive it through some communication channel */
if (ed25519_create_seed(seed)) {
    printf("error while generating seed\n");
    exit(1);
}
else {
    printf("\nNEW SEED: ");
    for(int i=0;i<32; i++) {
        printf("%02x",seed[i]);
    } 
    printf("\n");
}

ed25519_create_keypair(other_public_key, other_private_key, seed);

printf("NEW PUBLIC KEY: ");
for(int i=0;i<32; i++) {
    printf("%02x",other_public_key[i]);
} 
printf("\n");
printf("NEW PRIVATE KEY: ");
for(int i=0;i<64; i++) {
    printf("%02x",other_private_key[i]);
} 
printf("\n");


/* do a key exchange with other_public_key */
ed25519_key_exchange(shared_secret, other_public_key, private_key);

printf("SHARED SECRET: ");
for(int i=0;i<32; i++) {
    printf("%02x",shared_secret[i]);
} 
printf("\n");

/* 
    the magic here is that ed25519_key_exchange(shared_secret, public_key,
    other_private_key); would result in the same shared_secret
*/
}
