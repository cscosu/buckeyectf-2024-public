## About

Author: corgo

`forensics` `medium`

Crack open encrypted .pdf without needing to know the password

## Solve

- `exiftool` reports the PDF as using 40-bit encryption
- extract pdf 'hash' using pdf2john
- use hashcat's `-m 10410` to directly attack decryption key (versus `-m 10400` which tries passwords)
- use `qpdf` to open the pdf with this raw key, or use `-m 10420` to find a password that coincidentally 'collides' to that 40-bit key

command TLDR:

`python3 pdf2john.py protected-cia-document.pdf`

`hashcat -m 10410 -a3 "$pdf_hash" ?b?b?b?b?b -O`

if you want to decrypt with the raw key:

`qpdf --password=$raw_key --password-is-hex-key --decrypt protected-cia-document.pdf unprotected-cia-document.pdf`

if you want to find a password that collides to that key:

`hashcat -m 10420 -a3 "$pdf_hash:$raw_key" ?a?a?a?a?a?a?a -O`