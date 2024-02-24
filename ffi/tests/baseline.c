#include <stdio.h>
#include "../fips203.h"

int main(int argc, const char **argv) {
  MLKEM_encaps_key encaps;
  MLKEM_decaps_key decaps;
  MLKEM_ciphertext ct;
  ml_kem_shared_secret ssk_a;
  ml_kem_shared_secret ssk_b;
  ml_kem_err err;
  MLKEM_encaps_key encaps_weird;
  MLKEM_decaps_key decaps_weird;

  if (MLKEM_keygen (&encaps, &decaps))
      return 1;

  printf("Encaps (%d): ", MLKEM_size);
  for (int n = 0; n < sizeof(encaps.data); n++)
    printf ("%02x ", encaps.data[n]);
  printf("\n");
  
  printf("Decaps (%d): ", MLKEM_size);
  for (int n = 0; n < sizeof(decaps.data); n++)
    printf ("%02x ", decaps.data[n]);
  printf("\n");

  if (MLKEM_encaps (&encaps, &ct, &ssk_a))
    return 2;

  printf("Ciphertext (%d): ", MLKEM_size);
  for (int n = 0; n < sizeof(ct.data); n++)
    printf ("%02x ", ct.data[n]);
  printf("\n");

  printf("Shared Secret A: ");
  for (int n = 0; n < sizeof(ssk_a.data); n++)
    printf ("%02x ", ssk_a.data[n]);
  printf("\n");

  if (MLKEM_decaps (&decaps, &ct, &ssk_b))
    return 3;

  printf("Shared Secret B: ");
  for (int n = 0; n < sizeof(ssk_b.data); n++)
    printf ("%02x ", ssk_b.data[n]);
  printf("\n");

  if (! MLKEM_keygen (&encaps, NULL)) {
    fprintf (stderr, "keygen should have failed with NULL decaps\n");
    return 1;
  }
  if (! MLKEM_keygen (NULL, &decaps)) {
    fprintf (stderr, "keygen should have failed with NULL encaps\n");
    return 1;
  }
  if (! MLKEM_keygen (NULL, NULL)) {
    fprintf (stderr, "keygen should have failed with NULL encaps and decaps\n");
    return 1;
  }


  if (! MLKEM_encaps (&encaps, &ct, NULL)) {
    fprintf (stderr, "encaps should have failed with NULL shared_secret_out\n");
    return 1;
  }
  if (! MLKEM_encaps (&encaps, NULL, &ssk_a)) {
    fprintf (stderr, "encaps should have failed with NULL ciphertext_out\n");
    return 1;
  }
  if (! MLKEM_encaps (NULL, &ct, &ssk_a)) {
    fprintf (stderr, "encaps should have failed with NULL encaps_key\n");
    return 1;
  }
  if (! MLKEM_encaps (NULL, NULL, NULL)) {
    fprintf (stderr, "encaps should have failed with NULL arguments\n");
    return 1;
  }


  if (! MLKEM_decaps (&decaps, &ct, NULL)) {
    fprintf (stderr, "decaps should have failed with NULL shared_secret_out\n");
    return 1;
  }
  if (! MLKEM_decaps (&decaps, NULL, &ssk_b)) {
    fprintf (stderr, "decaps should have failed with NULL ciphertext\n");
    return 1;
  }
  if (! MLKEM_decaps (NULL, &ct, &ssk_b)) {
    fprintf (stderr, "decaps should have failed with NULL decaps_key\n");
    return 1;
  }
  if (! MLKEM_decaps (NULL, NULL, NULL)) {
    fprintf (stderr, "decaps should have failed with NULL arguments\n");
    return 1;
  }

  for (int i = 0; i < sizeof(encaps_weird.data); i++)
    encaps_weird.data[i] = 0xff;
  err = MLKEM_encaps (&encaps_weird, &ct, &ssk_a);
  if (err != ML_KEM_DESERIALIZATION_ERROR) {
    fprintf (stderr, "encaps against an encaps_key of all 0xff octets should have failed with deserialization error, got %d\n", err);
    return 1;
  }

  for (int i = 0; i < sizeof(decaps_weird.data); i++)
    decaps_weird.data[i] = 0xff;
  err = MLKEM_decaps (&decaps_weird, &ct, &ssk_a);
  if (err != ML_KEM_DECAPSULATION_ERROR) {
    fprintf (stderr, "decaps against a tampered decaps_key should have failed with decapsulation error, got %d\n", err);
    return 1;
  } 
  
  return 0;
}
