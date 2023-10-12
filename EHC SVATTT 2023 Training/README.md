# **EHC SVATTT 2023 TRAINING**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving:**
### CRY301

*server.py*
```python3
import random
import socketserver
import sys


def easyone(x):
    assert(x < 2 ** 128)
    x ^= x >> (64 + 19)
    x *= 0xd3856e824d9c8a26aef65c0fe1cc96db
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 3)
    x *= 0xe44035c8f8387dc11dd3dd67097007cb
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 20)
    x *= 0xc9f54782b4f17cb68ecf11d7b378e445
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 2)
    return x


def alittlebitharderone(x):
    assert(x < 2 ** 128)
    x ^= x >> 19
    x *= 0xd3856e824d9c8a26aef65c0fe1cc96db
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 3
    x *= 0xe44035c8f8387dc11dd3dd67097007cb
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 20
    x *= 0xc9f54782b4f17cb68ecf11d7b378e445
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> 2
    return x


def rewards():
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read()
            return b'Congrats, here is your flag: %s' % (flag)
    except Exception as e:
        print(e)
        return b'Server is not configured correctly. Please contact admins to fix the problem'


class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        try:
            secret_number = random.randint(2**127, 2**128)
            self.request.sendall(b'First round: ',)
            self.request.sendall(str(easyone(secret_number)).encode())
            self.request.sendall(b'\n')

            # Yes, I do allow you to try multiple times. But please
            # remember that this is NOT a bruteforce challenge.
            while True:
                try:
                    self.request.sendall(b'What is the secret number? ')
                    s = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue

                if s != secret_number:
                    self.request.sendall(b'Oops\n')
                    continue

                break

            secret_number = random.randint(2**127, 2**128)
            self.request.sendall(b'Second round: ',)
            self.request.sendall(
                str(alittlebitharderone(secret_number)).encode())
            self.request.sendall(b'\n')

            while True:
                try:
                    self.request.sendall(b'What is the secret number? ')
                    s = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue

                if s != secret_number:
                    self.request.sendall(b'Oops\n')
                    continue

                break

            # if you reach here, you deserve a reward!!!
            print("{} solved the challenge".format(self.client_address[0]))
            self.request.sendall(rewards())
            self.request.sendall(b'\n')

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("{} disconnected".format(self.client_address[0]))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def main(argv):
    host, port = '0.0.0.0', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)
```
Ở đây, chương trình sẽ in ra kết quả của hàm *easyone(x)* và bắt người dùng nhập vào giá trị $x$ ban đầu. Nếu đúng, chương trình sẽ trả về kết quả của hàm *alittlebitharderone(x)* và bắt người dùng nhập vào giá trị $x$ ban đầu. Nếu đúng lần nữa sẽ trả về flag.

Thử phân tích hàm *easyone*:
```python3
def easyone(x):
    assert(x < 2 ** 128)
    x ^= x >> (64 + 19)
    x *= 0xd3856e824d9c8a26aef65c0fe1cc96db
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 3)
    x *= 0xe44035c8f8387dc11dd3dd67097007cb
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 20)
    x *= 0xc9f54782b4f17cb68ecf11d7b378e445
    x &= 0xffffffffffffffffffffffffffffffff
    x ^= x >> (64 + 2)
    return x
```

Ở đây, điều kiện của x là nhỏ hơn 128-bit. Để ý thì giá trị x được chương trình nhập vào cũng sẽ luôn là 128 bit (secret_number = random.randint(2 ** 127, 2 ** 128)) nên ta không cần lo đến lắm.

Tiếp theo là hàng loạt các phép tính, tuy nhiên gói gọn chỉ có phép XOR với x được dịch phải 1 số lượng nào đó, cùng với đó là phép nhân và XOR với 0xffffffffffffffffffffffffffffffff để giữ lại 128-bit. Vì vậy, mình chỉ cần viết hàm reverse 2 phép tính đó là được.

Nếu các bạn đã đọc wu mình viết nhiều lần thì có thể dễ dàng viết được 2 hàm này
```python3
from Crypto.Util.number import *

def rev_xor_shift_right_func(data, num):
    data = format(data, "0128b")
    cal_data = [0]*num
    for i in range(128):
        cal_data.append(cal_data[i] ^ int(data[i]))
    return int("".join(str(i) for i in cal_data[num:]), 2)

def rev_mul_func(data, mul):
    return (data * int(inverse(mul, 0xffffffffffffffffffffffffffffffff + 1))) & 0xffffffffffffffffffffffffffffffff
```
Việc còn lại chỉ là sử dụng pwntool để connect tới server. Lưu ý code này các bạn có thể viết hoàn toàn ngắn hơn.
```python3
from pwn import *

conn = remote('0.0.0.0', '8000')

easy = int(conn.recvline().decode()[13:])
first = rev_xor_shift_right_func(easy, 66)
second = rev_mul_func(first, 0xc9f54782b4f17cb68ecf11d7b378e445)
third = rev_xor_shift_right_func(second, 84)
forth = rev_mul_func(third, 0xe44035c8f8387dc11dd3dd67097007cb)
fifth = rev_xor_shift_right_func(forth, 67)
sixth = rev_mul_func(fifth, 0xd3856e824d9c8a26aef65c0fe1cc96db)
final = rev_xor_shift_right_func(sixth, 83)

conn.sendline(str(final).encode())

harder = int(conn.recvline().decode()[41:])
first = rev_xor_shift_right_func(harder, 2)
second = rev_mul_func(first, 0xc9f54782b4f17cb68ecf11d7b378e445)
third = rev_xor_shift_right_func(second, 20)
forth = rev_mul_func(third, 0xe44035c8f8387dc11dd3dd67097007cb)
fifth = rev_xor_shift_right_func(forth, 3)
sixth = rev_mul_func(fifth, 0xd3856e824d9c8a26aef65c0fe1cc96db)
final = rev_xor_shift_right_func(sixth, 19)

conn.sendline(str(final).encode())

print(conn.recvline())
```

Flag: *EHCCTF{5h1ft_t0_th3_d3ath}*

### CRY302
*source.py*
```python3
import datetime
import os
import random
import socketserver
import sys
from base64 import b64decode, b64encode
from hashlib import sha512


def get_flag():
    try:
        with open('flag.txt', 'rb') as f:
            flag = f.read()
            return flag
    except Exception as e:
        print(e)
        return b'Server is not configured correctly. Please contact admins to fix the problem'


items = [
    (b'Fowl x 3', 1),
    (b'Mora x 30000', 100),
    (b'Mystic Enhancement Ore x 5', 500),
    (b'Hero\'s Wits x 3', 1000),
    (b'Primogems x 40', 5000),
    (b'FLAG', 99999)
]


class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        self.signkey = os.urandom(random.randint(8, 32))
        print(len(self.signkey))
        self.money = random.randint(1, 2000)
        try:
            while True:
                self.menu()

                try:
                    self.request.sendall(b'Your choice: ')
                    opt = int(self.rfile.readline().decode())
                except ValueError:
                    self.request.sendall(
                        b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
                    continue
                if opt == 1:
                    self.list()
                elif opt == 2:
                    self.order()
                elif opt == 3:
                    self.confirm()
                elif opt == 4:
                    self.request.sendall(b'Bye~\n')
                    return
                else:
                    self.request.sendall(b'Ohh~\n')

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print("{} disconnected".format(self.client_address[0]))

    def menu(self):
        self.request.sendall(
            b'To celebrate `our` first anniversary, we are offering you tons of product at the best prices\n')
        self.request.sendall(b'You have $%d\n' % self.money)
        self.request.sendall(b'1. Available products\n')
        self.request.sendall(b'2. Order\n')
        self.request.sendall(b'3. Confirm order\n')
        self.request.sendall(b'4. Exit\n')

    def list(self):
        for idx, item in enumerate(items):
            self.request.sendall(b'%d - %s: $%d\n' %
                                 (idx + 1, item[0], item[1]))

    def order(self):
        try:
            self.request.sendall(b'ID: ')
            pid = int(self.rfile.readline().decode())
        except ValueError:
            self.request.sendall(
                b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
            return

        if pid < 1 or pid > len(items):
            self.request.sendall(b'Ohh~\n')
            return

        payment = b'product=%s&price=%d&time=%.02f' % (
            items[pid-1][0], items[pid-1][1], datetime.datetime.now().timestamp())
        signature = sha512(self.signkey+payment).hexdigest()
        payment += b'&sign=%s' % signature.encode()
        self.request.sendall(b'Your order: ')
        self.request.sendall(b64encode(payment))
        self.request.sendall(b'\n')

    def confirm(self):
        try:
            self.request.sendall(b'Your order: ')
            payment = b64decode(self.rfile.readline().rstrip(b'\n'))
        except Exception:
            self.request.sendall(
                b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
            return

        pos = payment.rfind(b'&sign=')
        if pos == -1:
            self.request.sendall(b'Invalid order\n')
            return

        signature = payment[pos + 6:]
        if sha512(self.signkey+payment[:pos]).hexdigest().encode() != signature:
            self.request.sendall(b'Invalid order\n')
            return

        m = self.parse_qsl(payment[:pos])
        try:
            pname = m[b'product']
            price = int(m[b'price'])
        except (KeyError, ValueError, IndexError):
            self.request.sendall(b'Invalid order\n')
            return

        if price > self.money:
            self.request.sendall(b'Oops\n')
            return

        self.money -= price
        self.request.sendall(
            b'Transaction is completed. Your balance: $%d\n' % self.money)
        if pname == b'FLAG':
            print("{} solved the challenge".format(self.client_address[0]))
            self.request.sendall(b'Here is your flag: %s\n' % get_flag())
        else:
            self.request.sendall(
                b'%s will be delivered to your in-game mailbox soon\n' % pname)

    def parse_qsl(self, query):
        m = {}
        parts = query.split(b'&')
        for part in parts:
            key, val = part.split(b'=')
            m[key] = val
        return m


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def main(argv):
    host, port = '0.0.0.0', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)
```
Giao diện sử dụng:
```
To celebrate `our` first anniversary, we are offering you tons of product at the best prices
You have $846
1. Available products
2. Order
3. Confirm order
4. Exit
Your choice: 1
1 - Fowl x 3: $1
2 - Mora x 30000: $100
3 - Mystic Enhancement Ore x 5: $500
4 - Hero's Wits x 3: $1000
5 - Primogems x 40: $5000
6 - FLAG: $99999
To celebrate `our` first anniversary, we are offering you tons of product at the best prices
You have $846
1. Available products
2. Order
3. Confirm order
4. Exit
Your choice: 2
ID: 6
Your order: cHJvZHVjdD1GTEFHJnByaWNlPTk5OTk5JnRpbWU9MTY5NzA4OTk0Ni44OCZzaWduPTUwOWRiNDk4ODUzYWZhMjVmNWQ1MTQxNThiYzJjYjYzNTMyOTI5MzEwN2E3Yzc1MDhlODFhZWNiYTM0NWY3MTgzNzEyNDYwNDUxOGIwOTYyNTU0NjQ1OTNlNjliYTE5NDg5NGVmN2JhMDViYjM4Mjk1NjY0ZWM5OTVkZTA3MGVi
To celebrate `our` first anniversary, we are offering you tons of product at the best prices
You have $846
1. Available products
2. Order
3. Confirm order
4. Exit
Your choice: 3
Your order: cHJvZHVjdD1GTEFHJnByaWNlPTk5OTk5JnRpbWU9MTY5NzA4OTk0Ni44OCZzaWduPTUwOWRiNDk4ODUzYWZhMjVmNWQ1MTQxNThiYzJjYjYzNTMyOTI5MzEwN2E3Yzc1MDhlODFhZWNiYTM0NWY3MTgzNzEyNDYwNDUxOGIwOTYyNTU0NjQ1OTNlNjliYTE5NDg5NGVmN2JhMDViYjM4Mjk1NjY0ZWM5OTVkZTA3MGVi
Oops
```

Ở đây, chương trình cho chúng ta 1 số tiền được giới hạn bằng dòng ` self.money = random.randint(1, 2000)`. Có thể thấy, số tiền này không thể đủ để mua FLAG ($99999). Vậy phải làm như nào?

Hãy thử phân tích đoạn code để tạo ra mã order:
```python3
payment = b'product=%s&price=%d&time=%.02f' % (
            items[pid-1][0], items[pid-1][1], datetime.datetime.now().timestamp())
signature = sha512(self.signkey+payment).hexdigest()
payment += b'&sign=%s' % signature.encode()
self.request.sendall(b'Your order: ')
self.request.sendall(b64encode(payment))
```
Ở đây ta thấy order được cấu tạo từ 2 thành phần là payment và signature. Payment được cấu tạo từ 3 thành phần bao gồm tên `product`, `price`, và `time` là thời gian tạo order. Signature được tạo ra bằng cách mã hóa payment sử dụng SHA512 với `self.key` rồi chuyển sang hệ hexa. Payment được ghép với Signature bằng cụm `b'&sign='`. Order sẽ có dạng như này trước khi chuyển sang base64:
```
product=FLAG&price=99999&time=1697089946.88&sign=509db498853afa25f5d514158bc2cb635329293107a7c7508e81aecba345f71837124604518b096255464593e69ba194894ef7ba05bb38295664ec995de070eb
```

Khi mua chúng ta sẽ sử dụng hàm `confirm`
```python3
def confirm(self):
        try:
            self.request.sendall(b'Your order: ')
            payment = b64decode(self.rfile.readline().rstrip(b'\n'))
        except Exception:
            self.request.sendall(
                b'THIS IS A CRYPTOGRAPHIC CHALLENGE!!!\n')
            return

        pos = payment.rfind(b'&sign=')
        if pos == -1:
            self.request.sendall(b'Invalid order\n')
            return

        signature = payment[pos + 6:]
        if sha512(self.signkey+payment[:pos]).hexdigest().encode() != signature:
            self.request.sendall(b'Invalid order\n')
            return

        m = self.parse_qsl(payment[:pos])
        try:
            pname = m[b'product']
            price = int(m[b'price'])
        except (KeyError, ValueError, IndexError):
            self.request.sendall(b'Invalid order\n')
            return

        if price > self.money:
            self.request.sendall(b'Oops\n')
            return

        self.money -= price
        self.request.sendall(
            b'Transaction is completed. Your balance: $%d\n' % self.money)
        if pname == b'FLAG':
            print("{} solved the challenge".format(self.client_address[0]))
            self.request.sendall(b'Here is your flag: %s\n' % get_flag())
        else:
            self.request.sendall(
                b'%s will be delivered to your in-game mailbox soon\n' % pname)
```
Cách hoạt động của nó như sau:
- Chương trình sẽ decode đoạn base64, loại bỏ kí tự '\n'
- Tìm vị trí của chuỗi '&sign='. Nếu không tìm thấy trả về "Invalid order\n"
- Kiểm tra signature bằng cách mã hóa đoạn trước của '&sign=' bằng SHA512 và so sánh. Nếu không trùng, trả về "Invalid order\n"
- Tạo ra 1 dict chứa các key và value tương ứng cho từng tham số của order. Thực hiện qua hàm `parse_sql`:
```python3
def parse_qsl(self, query):
        m = {}
        parts = query.split(b'&')
        for part in parts:
            key, val = part.split(b'=')
            m[key] = val
        return m
```
- Gán giá trị của product, price vào pname, price. Nếu lỗi, trả về "Invalid order\n"
- Cuối cùng, so sánh price với money của mình. Nếu nhỏ hơn => mua được => đưa cho người dùng sản phẩm tên pname

Ở đây, điều duy nhất chúng ta có thể làm là khai thác đoạn tạo ra order bởi trong đó có chứa giá trị `price`. Vì đây là SHA512, ta có thể nghĩ tới kỹ thuật **Hash length Extension Attack**.

Về lý thuyết, các bạn có thể xem trên CyberJutsu:
- Vid 1: https://www.youtube.com/watch?v=9yOKVqayixM
- Vid 2: https://www.youtube.com/watch?v=GnCTXf_avdo

Độ dài của secret key sẽ phải brute force. Malicious data của mình sẽ là `&product=FLAG&price=1` để đảm bảo sau hàm `parse_sql` giá của FLAG sẽ là 1.

Để tạo payload, mình sẽ sử dụng tool sau
https://github.com/viensea1106/hash-length-extension

```python3
from pwn import *
import HashTools
from base64 import b64decode, b64encode

conn = remote('0.0.0.0', '8000')

def getMenu():
    for _ in range(6):
        conn.recvline()

getMenu()
conn.sendline(b'2')
conn.sendline(b'6')
order_data = conn.recvline().decode().strip()[29:]
order_data = b64decode(order_data).decode()

original_data = order_data[:43].encode()
signature = order_data[49:]
append_data = b'&product=FLAG&price=1'

magic = HashTools.new("sha512")


for i in range(8,32):
    getMenu()
    new_data, new_signature = magic.extension(
        secret_length=i, original_data=original_data,
        append_data=append_data, signature=signature
    )
    new_data += b'&sign=' + new_signature.encode()
    payload = b64encode(new_data)
    conn.sendline(b'3')
    conn.sendline(payload)
    if b'Transaction' in conn.recvline():
        break

print(conn.recvline())

```

Flag: *EHCCTF{h45h_l3ngth_3xt3ns10n_4tt4ck}*

**© 2023,Pham Quoc Trung. All rights reserved.**

