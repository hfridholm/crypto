# Notes
- Rename crypto program to only focus on AES (and rewrite .man)
- In aes decrypt, check if the message size is over 16
  (enough to be encrypted using aes)
- Rewrite the aes_encrypt function (and aes_decrypt), to not seg fault if message is under 16 bytes.

# Maybe
- Encrypt AES key in header of encrypted file
  (that way, you can know if it is decrypted or not)
  (input that the file should be formatted this way)
