#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/bn.h>

int main(int argc, char **argv)
{
  int res;

  BN_CTX *const bnCtx = BN_CTX_new();

  BIGNUM *a = NULL;
  BIGNUM *b = NULL;
  BN_dec2bn(&a, "12345");
  BN_dec2bn(&b, "23456");

  BIGNUM *r = BN_new();

  BN_add(r, a, b);

  char *const resStr = BN_bn2dec(r);
  fprintf(stdout, "Result: %s\n", resStr);
  free(resStr);

error:
  BN_free(b);
  BN_free(a);
  BN_CTX_free(bnCtx);
  return 0;
}
