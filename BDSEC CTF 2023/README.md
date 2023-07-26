# **BDSEC\_CTF\_2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**

Giải kẹt ghê gớm cho những 1 challenge Crypto :v 

### Easy Crypto
Someone sent me this message : **1e25v768h1e66dw61v1hv1kl6aa1ei1pw1pv1ju1kj5ps1bb6lw624**\
What is this ?

Flag Format : **BDSEC{flag_here}**

*Author : NomanProdhan*

Với bài này thì mình mất kha khá thời gian để có thể tìm ra rằng flag bị mã hóa bằng Twin-Hex cipher. Mình sử dụng trang web [này](https://www.calcresult.com/misc/cyphers/twin-hex.html) để tìm hiểu về nó cũng như decrypt. Kết quả sau khi decrypt:

```
2jo3t12nv4qc4355tr2z74734z53m01gy4ql
```

Vẫn chưa ra flag, tuy nhiên trông nó vẫn khá giống form của Twin-Hex cipher. Vì vậy, mình đã thử ấn decrypt lần nữa và có được flag

Để tiện sau này thì mình có viết code python để giải Twin-Hex cipher: [easycrypto.py](https://github.com/AcceleratorHTH/CTF-Writeup/blob/main/BDSEC%20CTF%202023/Source/easycrypto.py)

Flag: BDSEC{\_tW1n_H3X_c1Ph3r_}


**© 2023,Pham Quoc Trung. All rights reserved.**
