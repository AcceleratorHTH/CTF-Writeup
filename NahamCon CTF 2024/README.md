# NahamCon CTF 2024

## **NAHAMCON CTF 2024**

## **CRYPTOGRAPHY WRITEUP**

## **Author:**

* Pham Quoc Trung

## **Used Language:**

* Python3

## **Problem Solving:**

### **MagicRSA**

#### **Description:**

Here's an RSA challenge using the most magical number of all.

#### Attachment:

_rsa\_with\_a\_magic\_number.py_

```python
from secrets import randbits
from sympy import nextprime

e = 3

def encrypt(inp):
	p = nextprime(randbits(2048))
	q = nextprime(randbits(2048))
	n = p * q
	enc = [pow(ord(c), e, n) for c in inp]
	return [n, enc]

plaintext = open('flag.txt').read()

with open('output.txt', 'w') as f:
    data = encrypt(plaintext)
    f.write(f'Semiprime:\nN: {data[0]}\nCiphertext:\n')
    f.write(''.join(f'{b} ' for b in data[1]))
    f.write('\n\n')
```

