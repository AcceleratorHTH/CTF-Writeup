from pwn import remote
from Crypto.Util.number import isPrime, long_to_bytes
from string import ascii_letters, digits
from itertools import combinations
from sympy import divisors
from math import log2

# Hàm để giải quyết XOR
def decrypt_flag(encrypt_hex):
    encrypt = bytes.fromhex(encrypt_hex)
    key_form = b'EHC{'
    
    # Tính ra được 4 chữ cái đầu của key là "TRUNG", tên author là "TRUNGPQ" => key
    key = [s1 ^ s2 for (s1, s2) in zip(encrypt, key_form)] + [ord("G"), ord("P"), ord("Q")]

    flag = []
    for i in range(len(encrypt)):
        flag.append(encrypt[i] ^ key[i % len(key)])

    return ''.join(chr(c) for c in flag)

def main():
    # Khởi tạo kết nối tới máy chủ CTF qua port 2706
    conn = remote('riven-shaco-alistar-ed6e0cb4.dailycookie.cloud', 32383)

    # Đọc output từ máy chủ
    output = conn.recvlines(2) 

    # Lấy thông tin từ output
    chogath = int(output[0].split(b': ')[1].decode())
    draven = int(output[1].split(b': ')[1].decode())
    ezreal = 65537

    # Tính toán
    divisor = divisors(draven * ezreal - 1) # Tìm tất cả các ước của e*d - 1
    primes = [x + 1 for x in divisor if isPrime(x + 1)] # Tìm tất cả các ước mà khi + 1 là số nguyên tố
    correct_size_primes = [x for x in primes if log2(x) // 1 == 127] # Tìm tất cả các số nguyên tố trong tập hợp ban nãy mà là 128-bit

    charset = ascii_letters + digits # Tạo ra một charset bao gồm ascii_letters và digits

    org_message = [] # Khởi tạo biến lưu kết quả
    for p, q in combinations(correct_size_primes, 2):
        try:
            # Với mỗi bộ p, q trong các set lấy 2 số ở tập hợp bên trên, thử decrypt m = c^d (mod n)
            s = long_to_bytes(pow(chogath, draven, p * q)).decode("ascii")

            # Nếu tất cả các kí tự trong chuỗi được decrypt đều là letter và digits => Chèn giá trị s vào org_message
            if all([c in charset for c in s]):
                org_message.append(s)
        except Exception:
            continue

    # Gửi kết quả tới máy chủ
    conn.sendline(org_message[0])

    # Các dòng trước flag:
    conn.recvuntil(b'reward:').decode()
    
    # Nhận flag bị mã hóa
    encrypted_flag = conn.recvall().decode()
    
    # Giải mã flag
    flag = decrypt_flag(encrypted_flag.strip())

    # In ra flag
    print(flag)

if __name__ == "__main__":
    main()
