# crapto1 - Recovery the mifare classic key

Utilities extract keys from nonces collected during the authentication process

## Compilation

> [!TIP]
> Arch Linux users can install crapto1 from [AUR](https://aur.archlinux.org/packages/crapto1)

1. Clone repo
- `git clone https://github.com/li0ard/crapto1 && cd crapto1/`
2. Compile using `make`
- `make`

## Usage
### mf32

`mf32` working with two sets of 32 bits of keystream authentication.

Syntax: `./mf32 <uid> <tag_challenge> <reader_challenge> <reader_response> <tag_challenge2> <reader_challenge2> <reader_response2>`
- Example: `./mf32 23A12659 182c6685 3893952A 9613a859 b3aac455 f05e18ac 2c479869`

### mf64

`mf64` working with one set of 64 bit keystream authentication.

Syntax: `./mf64 <uid> <tag_challenge> <nr_enc> <reader_response> <tag_response>`
- Example: `./mf64 c108416a ABCD1949 59D5920F 15B9D553 A79A3FEE`

### n2k

`n2k` working with parity and keystream nonces
Syntax: `./n2k <uid> <nt> <par> <ks>`
- Example: `./n2k e9cadd9c a8bf4a12 a020a8285858b090 050f010607060e07`

## Acknowledgements

 - [bla Code](https://github.com/ErnyTech/crapto1)