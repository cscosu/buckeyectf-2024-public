## About

Author: corgo

`forensics` `hard`

Crack randomly-generated 12-character .zip password by abusing ZipCrypto vulnerabilities

## Solve

- .zip is using zipcrypto, which is vulnerable to a known-plaintext attack
- use bkcrack to open .zip without the password, using the PNG header (`89504E470D0A1A0A0000000D49484452`) as known plaintext
- .zip decryption keys can be used to get the first 6 characters of the password
- hashcat/bkcrack can crack the last 6

command TLDR:

`bkcrack.exe -C dogs_wearing_tools.zip -c 1.png -x 0 89504E470D0A1A0A0000000D49484452`

after a minute or two that'll spit out the internal decryption keys (adf73413 6f6130e7 0cfbc537).
hashcat use these decryption keys to bruteforce the original password

`hashcat -m20510 -a3 adf734136f6130e70cfbc537 ?a?a?a?a?a?a`

this gets the original password in ~30 seconds, `2n3Ad3&ZxDvV`, which lets you open the .7z and grab the flag 