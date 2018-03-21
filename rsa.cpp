#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include "rsa.hpp"

HASH gcd(HASH a, HASH b) {
  HASH c;
  while (a != 0) {
    c = a;
    a = b % a;
    b = c;
  }
  return b;
}

HASH ExtEuclid(HASH a, HASH b) {
 HASH x = 0, y = 1, u = 1, v = 0,
      gcd = b,
      m, n, q, r;

 while (a != 0) {
   q = gcd / a; r = gcd % a;
   m = x - u * q; n = y - v * q;
   gcd = a;
   a = r; x = u; y = v; u = m; v = n;
 }
 return y;
}

//ERROR al encriptar
HASH modExp(HASH b, HASH e, HASH m) {
  if (b < 0 || e < 0 || m <= 0){
    exit(1);
  }
  b = b % m;
  if (e == 0) return 1;
  if (e == 1) return b;
  if ( e % 2 == 0){
    return (modExp(b * b % m, e/2, m) % m);
  }
  if (e % 2 == 1){
    return (b * modExp(b, (e-1), m) % m);
  }
  return 0;
}


void RSA::generateKeys(struct Keyring *keys, const char *primes_file) {
  srand(time(0));

  FILE *primes_list;
  char buffer[1024];
  const int MAX_DIGITS = 100;
  int i,j = 0;


  if(!(primes_list = fopen(primes_file, "r"))){
    fprintf(stderr, "Problem reading %s\n", primes_file);
    exit(1);
  }

  HASH prime_count = 0;
  do {
    int bytes_read = fread(buffer,1,sizeof(buffer)-1, primes_list);
    buffer[bytes_read] = '\0';
    for (i=0 ; buffer[i]; i++){
      if (buffer[i] == '\n'){
        prime_count++;
      }
    }
  }
  while (feof(primes_list) == 0);


  HASH p = 0;
  HASH q = 0;

  HASH e = powl(2, 8) + 1;
  HASH d = 0;
  char prime_buffer[MAX_DIGITS];
  HASH max = 0;
  HASH phi_max = 0;

  do {
    int a =  (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);
    int b =  (double)rand() * (prime_count + 1) / (RAND_MAX + 1.0);

    rewind(primes_list);
    for (i = 0; i < a + 1; i++){
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    p = atol(prime_buffer);

    rewind(primes_list);
    for (i = 0; i < b + 1; i++){
      for (j = 0; j < MAX_DIGITS; j++){
        prime_buffer[j] = 0;
      }
      fgets(prime_buffer, sizeof(prime_buffer) - 1, primes_list);
    }
    q = atol(prime_buffer);

    max = p*q;
    phi_max = (p - 1) * (q - 1);
  }
  while (!(p && q) || (p == q) || (gcd(phi_max, e) != 1));

  d = ExtEuclid(phi_max,e);
  while (d < 0){
    d += phi_max;
  }

  printf("primes %lld and %lld\n",(HASH)p, (HASH)q);

  keys -> e.modulus = max;
  keys -> e.exponent = e;
  keys -> d.modulus = max;
  keys -> d.exponent = d;
}

HASH *RSA::encrypt(const char *msg, const unsigned long size, struct Key *e) {
  HASH *encrypted = (HASH*)malloc(sizeof(HASH) * size);
  if (encrypted == NULL) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return 0;
  }

  for(HASH i = 0; i < size; i++){
    encrypted[i] = modExp(msg[i], e -> exponent, e -> modulus);
  }
  return encrypted;
}


char *RSA::decrypt(const HASH *msg, const unsigned long size, struct Key *d) {
  if (size % sizeof(HASH) != 0) {
    fprintf(stderr, "Error: size (%d)\n", (int)sizeof(HASH));
    return NULL;
  }

  char *decrypted = (char*)malloc(size / sizeof(HASH));
  if (!decrypted) {
    fprintf(stderr, "Error: Heap allocation failed.\n");
    return NULL;
  }

  for (HASH i = 0; i < size / 8; i++) {
    decrypted[i] = modExp(msg[i], d -> exponent, d -> modulus);
  }

  return decrypted;
}

void RSA::print(struct Keyring *keyring) {
  printf("Private key:\n Modulus: %llx\n Exponent: %llx\n",
      keyring -> d.modulus,
      keyring -> d.exponent);
  printf("Public key:\n Modulus: %llx\n Exponent: %llx\n",
      keyring -> e.modulus,
      keyring -> e.exponent);
}
