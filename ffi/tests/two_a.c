#include <stddef.h>
#include <fips203.h>

int from_b(void);

int main(void) {
  if (ml_kem_512_keygen(NULL, NULL) == ML_KEM_OK)
    return 1;
  if (from_b() != ML_KEM_DECAPSULATION_ERROR)
    return 2;
  return 0;
}
