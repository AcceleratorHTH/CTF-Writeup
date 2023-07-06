from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

def generate_random_string(length):
    return "".join(choice(ascii_letters + digits) for _ in range(length))

def encrypt_flag(flag):
    flag = flag.encode() 
    key = ###SECRET###

    res = []
    for i in range(len(flag)):
        res.append(flag[i] ^ ord(key[i % len(key)]))

    hex_flag = ''.join(format(c, '02x') for c in res)
    return hex_flag

def get_flag(message):
    print("Question: What did Malphite say?")
    answer = input("Enter your answer: ").strip()

    if answer == malphite:
        print("Nice! You got it right.")
        print("Heres your reward:")
        with open("/flag.txt") as f:
            reward = f.read().strip()
            flag = encrypt_flag(reward)
            print(flag)
    else:
        print("Oops! Thats not the correct answer.")
        print("Maybe next time?")   

malphite = generate_random_string(16)
poppy = getPrime(128)
quinn = getPrime(128)
nasus = poppy * quinn
ezreal = 65537

draven = inverse(ezreal, (poppy - 1) * (quinn - 1))

chogath = pow(bytes_to_long(malphite.encode()), ezreal, nasus)

print(f"Chogath: {chogath}")
print(f"Draven: {draven}")

get_flag(malphite)



