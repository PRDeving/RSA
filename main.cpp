#include "rsa.hpp"
#include <stdio.h>
#include <string.h>

int main() {
  RSA::Keyring keyring;
  generateKeys(&keyring);
  RSA::print(&keyring);

  char *secret = (char*)"esto es un test del poder del RSA y de mi nardo moreno!!!";
  printf("\nmsg: %s\n", secret);

  HASH *crypt = RSA::encrypt(secret, strlen(secret), &keyring.e);
  printf("\ncrypt: %llx\n", *crypt);

  char *decrypt = RSA::decrypt(crypt, 8 * strlen(secret), &keyring.d);
  printf("decrypt: %s\n", decrypt);
}
