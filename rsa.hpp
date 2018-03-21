#ifndef RSA_HPP
#define RSA_HPP

#ifndef PRIMES_FILE_PATH
#define PRIMES_FILE_PATH "primes.txt"
#endif

typedef long long HASH;

namespace RSA {
  struct Key {
    HASH modulus;
    HASH exponent;
  };

  struct Keyring {
    struct Key d;
    struct Key e;
  };

  void generateKeys(struct Keyring *keys, const char *primes_file = PRIMES_FILE_PATH);
  HASH *encrypt(const char *msg, const unsigned long size, struct Key *e);
  char *decrypt(const HASH *msg, const unsigned long size, struct Key *d);
  void print(struct Keyring *keyring);
}

#endif
