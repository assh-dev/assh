# assh — It's SSH, but ASSh

`assh` is an implementation of SSH...  
but it's **less secure** and **blazingly slow**.

Named it "assh" so I can say:  
> _"It's SSH but ASSh"_ 

But hey, I'm proud of it.

Just a final year student messing around with cryptography and sockets, trying to understand how SSH works from scratch.

---

## What it does (so far)

- Does a janky but working **Diffie-Hellman key exchange**
- Uses **AES-CTR** for symmetric encryption
- Uses **SHA256** for hashing stuff
- Sends and receives commands over a TCP socket (with encryption)
- Uses big integers via **LibTomMath**

Basically, you can run a server and client and send encrypted messages

---

## How to build

Clone the repo, `cd` into it, then:

```bash
make
```

---

## Stuff I didn’t write

### AES (Brian Gladman)
I’m using [Brian Gladman’s AES implementation](https://github.com/BrianGladman/aes) in CTR mode
You can find it in `crypto/aes/`

### SHA256 (Zedwood)
For SHA256, I used [zedwood's single-file SHA256 implementation](http://www.zedwood.com/article/cpp-sha256-function).  
You can find it at `crypto/hashing/sha256.cpp`

### Big Ints (LibTomMath)
Used [LibTomMath](https://github.com/libtom/libtommath) for doing big int math
It’s public domain and handles all the modular exponentiation stuff in DH

---

## Why I did this🙃

Wanted to learn how SSH kinda works under the hood
Also wanted to touch some actual crypto code instead of just using OpenSSL as a black box.

---

## License

All the third-party code is public domain or BSD, and credit is given above.  
My own code? Feel free to read, learn from it, or laugh at it. Attribution appreciated but not required.

---
