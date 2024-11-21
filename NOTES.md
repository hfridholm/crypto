# Notes
- allocate the result memory in skey_encode instead of filling result.

## Must
- keygen generates keys that always work with each other!

## Maybe
- Encrypt AES key in header of encrypted file
  (that way, you can know if it is decrypted or not)
  (input that the file should be formatted this way)
