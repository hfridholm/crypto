# Notes
- allocate the result memory in skey_encode instead of filling result.
- add quiet/silent argument to the utilities, and output messages
- write good README.md

## Must
- keygen generates keys that always work with each other!
  (it seams like keys 1024-bit and over have this problem)

## Maybe
- hide structure of skey and pkey
  (this requires pointer to skey and pkey in keygen.c and asmcpt.c)
