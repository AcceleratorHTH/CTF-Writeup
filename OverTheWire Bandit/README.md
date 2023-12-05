# **OverTheWire**

# **BANDIT WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving**
### Level 0
Des: https://overthewire.org/wargames/bandit/bandit0.html

Với challenge đầu tiên, mình chỉ cần sử dụng dòng lệnh sau:
`ssh bandit0@bandit.labs.overthewire.org -p 2220`

### Level 0 → Level 1
Des: https://overthewire.org/wargames/bandit/bandit1.html

Sử dụng lệnh `ls` để xem trong directory hiện tại có những file nào
```bash
bandit0@bandit:~$ ls
readme
```
Mình dùng lệnh `cat` để xem nội dung file readme và lấy được pass cho level tiếp theo
```bash
bandit0@bandit:~$ cat readme
NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL
```

### Level 1 → Level 2
Des: https://overthewire.org/wargames/bandit/bandit2.html

Ở đây khi `ls` ta thấy có một file tên là "-". Điều này làm cho khi ta chạy lệnh `cat -` bình thường sẽ không được vì dấu - thường dùng để xác định option.

Ở đây, mình có thể sử dụng "--" để chỉ định rằng các tham số sau đó không phải là tùy chọn. Nó sẽ hoạt động khi file có dạng "-abcxyz". Còn ở đây, mình sẽ dùng như sau:
```bash
bandit1@bandit:~$ cat ./-
rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
```
Mình đã dùng "./-" để xác định "-" là 1 tệp nằm trong directory hiện tại.


Tham khảo: https://stackoverflow.com/questions/42187323/how-to-open-a-dashed-filename-using-terminal

Các cách khác như link tham khảo:
```bash
bandit1@bandit:~$ rev - | rev
rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi

bandit1@bandit:~$ cat < -
rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
```

### Level 2 → Level 3
Des: https://overthewire.org/wargames/bandit/bandit3.html

Ở đây thì file chứa password có chứa dấu cách, mình chỉ cần đặt tên file trong "" để xác định nó là một chuỗi là oke

```bash
bandit2@bandit:~$ cat "spaces in this filename"
aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
```

### Level 3 → Level 4
Des: https://overthewire.org/wargames/bandit/bandit4.html

Khi `ls` mình thấy có một folder tên "inhere". Sử dụng lệnh `cd` để truy cập vào nó
```bash
bandit3@bandit:~$ ls
inhere
bandit3@bandit:~$ cd inhere
```

Khi `ls` bình thường sẽ không ra file gì. Ở đây mình sẽ sử dụng lệnh `ls -a` để hiển thị ra file ẩn. Trong linux, file ẩn sẽ có dấu "." ở đầu

```bash
bandit3@bandit:~/inhere$ ls
bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
```

Sử dụng `cat` để lấy password
```bash
bandit3@bandit:~/inhere$ cat .hidden
2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe
```

### Level 4 → Level 5
Des: https://overthewire.org/wargames/bandit/bandit5.html

Ở đây sau khi vào thư mục "inhere" ta sẽ thấy có 9 file
```bash
bandit4@bandit:~/inhere$ ls
-file00  -file01  -file02  -file03  -file04  -file05  -file06  -file07  -file08  -file09
```

Các bạn có thể `cat` từng file để kiếm password, hoặc sử dụng `cat -- -file0*` để `cat` tất cả các file. Tuy nhiên có vẻ hơi rối.

Dựa vào việc file chứa password sẽ là các kí tự human-readable, mình chỉ cần tìm ra file chứa ASCII. Ở đây, mình có thể sử dụng lệnh `file` để thực hiện

```bash
bandit4@bandit:~/inhere$ file -- *
-file00: data
-file01: data
-file02: data
-file03: data
-file04: data
-file05: data
-file06: data
-file07: ASCII text
-file08: data
-file09: data
```
Nhận thấy file "-file07" là ASCII text, mình `cat` và lấy được password

```bash
bandit4@bandit:~/inhere$ cat ./-file07
lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
```

### Level 5 → Level 6
Des: https://overthewire.org/wargames/bandit/bandit6.html

Ở đây, trong folder "inhere" chứa rất nhiều các folder khác, và trong từng folder có rất nhiều file

```bash
bandit5@bandit:~/inhere$ ls
maybehere00  maybehere03  maybehere06  maybehere09  maybehere12  maybehere15  maybehere18
maybehere01  maybehere04  maybehere07  maybehere10  maybehere13  maybehere16  maybehere19
maybehere02  maybehere05  maybehere08  maybehere11  maybehere14  maybehere17
```
Dựa vào các tiêu chí của file cần tìm như sau:
- human-readable
- 1033 bytes in size
- not executable

Ở đây, mình sẽ sử dụng lệnh `find`. Do lệnh find có sẵn option về size, mình sẽ sử dụng dữ kiện đó trước. 
```bash
bandit5@bandit:~/inhere$ find . -size 1033c
./maybehere07/.file2
```
Ở đây thì bài này chỉ có mỗi 1 file 1033 bytes nên mình không cần dựa vào các tiêu chí khác nữa. Tuy nhiên, nếu có nhiều file hiện ra thì mình sẽ làm như sau. 

Thêm human-readable:
```bash
bandit5@bandit:~/inhere$ find . -size 1033c -exec file {} \; | grep "ASCII text"
./maybehere07/.file2: ASCII text, with very long lines (1000)
```
Note: "{}" sẽ được thay thế bằng tên từng file tìm bởi lệnh `find`, "\\;"" đánh dấu kết thúc của mệnh đề `-exec`

Thêm not executable
```bash
bandit5@bandit:~/inhere$ find . -size 1033c -exec file {} \; ! -executable | grep "ASCII text"
./maybehere07/.file2: ASCII text, with very long lines (1000)
```
Lấy password:
```bash
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        

```

### Level 6 → Level 7
Des: https://overthewire.org/wargames/bandit/bandit7.html

Do folder hiện tại có vẻ không có gì, thử `cd ..` để lùi về directory cha. Và ta lại thấy rất nhiều folder
```bash
bandit6@bandit:/home$ ls
bandit0   bandit15  bandit21  bandit27-git  bandit30-git  bandit6    drifter12  drifter5     formulaone2  krypton4
bandit1   bandit16  bandit22  bandit28      bandit31      bandit7    drifter13  drifter6     formulaone3  krypton5
bandit10  bandit17  bandit23  bandit28-git  bandit31-git  bandit8    drifter14  drifter7     formulaone5  krypton6
bandit11  bandit18  bandit24  bandit29      bandit32      bandit9    drifter15  drifter8     formulaone6  krypton7
bandit12  bandit19  bandit25  bandit29-git  bandit33      drifter0   drifter2   drifter9     krypton1     ubuntu
bandit13  bandit2   bandit26  bandit3       bandit4       drifter1   drifter3   formulaone0  krypton2
bandit14  bandit20  bandit27  bandit30      bandit5       drifter10  drifter4   formulaone1  krypton3
```
Dựa trên 3 tiêu chí của file cần tìm
- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

Các thông số trên có thể được xem thông qua lệnh `ls -l`. Ví dụ: 
```bash
bandit6@bandit:/home$ ls -l
total 272
drwxr-xr-x 2 root         root         4096 Oct  5 06:19 bandit0
```
Ở đây, root thứ nhất là user, root thứ hai là group, 4096 bytes là size.

Để tìm file có các tiêu chí trên, các bạn có thể dùng `find` kết hợp exec ls -l, tuy nhiên trong `find` đã có sẵn các tùy chọn về user và group nên mình sẽ dùng luôn

```bash
bandit6@bandit:/home$ find . -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
```
Mình sử dụng `2>/dev/null` để không hiện các error message. Tuy nhiên có vẻ không tìm ra trong folder này. Thử tìm toàn bộ coi sao.
```bash
bandit6@bandit:/home$ find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
```

Và mình ra được pass:
```bash
bandit6@bandit:/home$ cat /var/lib/dpkg/info/bandit7.password
z7WtoNQU2XfjmMtWA8u5rN4vzqu4v99S
```

### Level 7 → Level 8
Des: https://overthewire.org/wargames/bandit/bandit8.html

Ở đây ta có file "data.txt" chứa rất nhiều user và password. Việc cần tìm là password của "millionth".

Sử dụng `grep`:
```bash
bandit7@bandit:~$ cat data.txt | grep millionth
millionth       TESKZC0XvTetK0S9xNwm25STk5iWrBvP
```

### Level 8 → Level 9
Des: https://overthewire.org/wargames/bandit/bandit9.html

Ở đây, ta có thể sử dụng `uniq -u` để lọc ra dòng không có duplicate. Tuy nhiên, dữ liệu đưa vào `uniq` phải được sắp xếp nên ta sẽ sử dụng thêm `sort`

```bash
bandit8@bandit:~$ sort data.txt | uniq -u
EN632PlfYiZbn3PhVK3XOGSlNInNE00t
```

### Level 9 → Level 10
Des: https://overthewire.org/wargames/bandit/bandit10.html

Ở đây, mình sẽ sử dụng `grep` để tìm các dấu "=" liền nhau, và sử dụng `strings` thay vì `cat` vì `grep` không dùng được nếu stdin có chứa dữ liệu không phải ASCII.

```bash
bandit9@bandit:~$ strings data.txt | grep "=="
x]T========== theG)"
========== passwordk^
========== is
========== G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
```

### Level 10 → Level 11
Des: https://overthewire.org/wargames/bandit/bandit11.html

Ở đây, khi đọc file "data.txt" ta được 1 đoạn mã base64:
```bash
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIDZ6UGV6aUxkUjJSS05kTllGTmI2blZDS3pwaGxYSEJNCg==
```
Có thể sử dụng các tool online như CyberChef để decode. Tuy nhiên, có thể sử dụng lệnh trên linux luôn như sau:
```bash
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is 6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM
```

### Level 11 → Level 12
Des: https://overthewire.org/wargames/bandit/bandit12.html

Sau khi đọc file "data.txt"ta được 1 đoạn mã ROT13:
```bash
bandit11@bandit:~$ cat data.txt
Gur cnffjbeq vf WIAOOSFzMjXXBC0KoSKBbJ8puQm5lIEi
```
Sử dụng bất kì tool nào trên mạng hoặc decode bằng tay, ta được:
```
The password is JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv
```

### Level 12 → Level 13
Des: https://overthewire.org/wargames/bandit/bandit13.html

Ở đây, khi xem file "data.txt" mình thấy được dữ liệu hexdump
```bash
bandit12@bandit:~$ cat data.txt
00000000: 1f8b 0808 6855 1e65 0203 6461 7461 322e  ....hU.e..data2.
00000010: 6269 6e00 013d 02c2 fd42 5a68 3931 4159  bin..=...BZh91AY
00000020: 2653 5948 1b32 0200 0019 ffff faee cff7  &SYH.2..........
00000030: f6ff e4f7 bfbc ffff bff7 ffb9 39ff 7ffb  ............9...
00000040: bd31 eeff b9fb fbbb b9bf f77f b001 3b2c  .1............;,
00000050: d100 0d03 d200 6868 0d00 0069 a00d 0340  ......hh...i...@
00000060: 1a68 00d0 0d01 a1a0 0001 a680 0003 46d4  .h............F.
00000070: 6434 3234 611a 340d 07a4 c351 068f 5000  d424a.4....Q..P.
00000080: 069a 0680 0000 0006 8006 8da4 681a 6868  ............h.hh
00000090: 0d06 8d00 6834 3400 d07a 9a00 01a0 0341  ....h44..z.....A
000000a0: ea1e a190 da40 3d10 ca68 3468 6800 00c8  .....@=..h4hh...
000000b0: 1a1a 1b50 0683 d434 d069 a0d0 3100 d000  ...P...4.i..1...
000000c0: 001e a680 00d0 1a00 d0d0 6864 d0c4 d0d0  ..........hd....
000000d0: 000c 8641 7440 0108 032e 86b4 4cf0 22bb  ...At@......L.".
000000e0: 6682 2b7e b3e2 e98d aa74 dacc 0284 330d  f.+~.....t....3.
000000f0: bbb2 9494 d332 d933 642a 3538 d27e 09ce  .....2.3d*58.~..
00000100: 53da 185a 505e aada 6c75 59a2 b342 0572  S..ZP^..luY..B.r
00000110: 249a 4600 5021 25b0 1973 c18a 6881 1bef  $.F.P!%..s..h...
00000120: 3f9b 1429 5b1d 3d87 68b5 804f 1d28 42fa  ?..)[.=.h..O.(B.
00000130: 16c2 3241 98fb 8229 e274 5a63 fe92 3aca  ..2A...).tZc..:.
00000140: 70c3 a329 d21f 41e0 5a10 08cb 888f 30df  p..)..A.Z.....0.
00000150: f3da ce85 418b 0379 6a65 cfa2 eeb7 9f01  ....A..yje......
00000160: 782c da0e 288b e0c3 fe13 7af5 45ab 2b22  x,..(.....z.E.+"
00000170: a432 bf2f e32d b9e6 1465 2296 d805 a45e  .2./.-...e"....^
00000180: d1c1 eacb 7483 6aac ca0e cf24 8864 bd40  ....t.j....$.d.@
00000190: 118c 644a 1dc6 a127 375c b7a6 c124 bdae  ..dJ...'7\...$..
000001a0: 6d31 63a0 a223 3ea0 61d4 bdf0 450f 56fb  m1c..#>.a...E.V.
000001b0: a546 8d34 08a2 4f1d 43d3 9063 404d dd43  .F.4..O.C..c@M.C
000001c0: b4f2 e65d bcb7 5932 0f5e 6802 3892 a988  ...]..Y2.^h.8...
000001d0: 443d 8e89 7e09 4fb0 499d ee4e 4470 46c0  D=..~.O.I..NDpF.
000001e0: 2ba6 7c62 234a 7f76 151b aec0 23ee 4a97  +.|b#J.v....#.J.
000001f0: bc64 e34c de8a 5724 a1c3 9b89 cd96 1879  .d.L..W$.......y
00000200: d560 0cbb 5c26 09e4 efaf 5b94 402a 7780  .`..\&....[.@*w.
00000210: 4d87 30ce b8a3 946e 72c1 a643 1db7 a060  M.0....nr..C...`
00000220: 6524 629c 0c7e 8e7b e0f8 820c d5cb 60a0  e$b..~.{......`.
00000230: 003c a584 d4c1 61ef eb02 3f65 3a54 a3a2  .<....a...?e:T..
00000240: a565 c154 34c2 b162 d206 1ff8 bb92 29c2  .e.T4..b......).
00000250: 8482 40d9 9010 b3a9 e478 3d02 0000       ..@......x=...
```

Đây có thể được gen ra bằng `xxd`. Mình sẽ sử dụng `xxd -r` để biến nó về dạng ban đầu.
```bash
bandit12@bandit:/tmp/trungpq$ xxd -r data.txt > data
bandit12@bandit:/tmp/trungpq$ file data
data: gzip compressed data, was "data2.bin", last modified: Thu Oct  5 06:19:20 2023, max compression, from Unix, original size modulo 2^32 573
```
Sau khi phục hồi, mình thu được một file gzip. Để giải nén, mình sử dụng lệnh `gzip -d`. Để làm được thì mình phải thêm đuôi .gz đã
```bash
bandit12@bandit:/tmp/trungpq$ mv data data.gz
bandit12@bandit:/tmp/trungpq$ gzip -d data.gz
bandit12@bandit:/tmp/trungpq$ ls
data
bandit12@bandit:/tmp/trungpq$ file data
data: bzip2 compressed data, block size = 900k
```
Sau khi giải nén mình thu được 1 file bzip2. Sử dụng `bzip2 -d` để giải nén
```bash
bandit12@bandit:/tmp/trungpq$ mv data data.bz2
bandit12@bandit:/tmp/trungpq$ bzip2 -d data.bz2
bandit12@bandit:/tmp/trungpq$ ls
data
bandit12@bandit:/tmp/trungpq$ file data
data: gzip compressed data, was "data4.bin", last modified: Thu Oct  5 06:19:20 2023, max compression, from Unix, original size modulo 2^32 20480
```
Tiếp tục thu được một file gzip. Làm tương tự
```bash
bandit12@bandit:/tmp/trungpq$ mv data data.gz
bandit12@bandit:/tmp/trungpq$ gzip -d data.gz
bandit12@bandit:/tmp/trungpq$ ls
data 
bandit12@bandit:/tmp/trungpq$ file data
data: POSIX tar archive (GNU)
```
Lần này thì thu được một file tar. Sử dụng `tar -xvf` để giải nén nó:
```bash
bandit12@bandit:/tmp/trungpq$ mv data data.tar
bandit12@bandit:/tmp/trungpq$ tar -xvf data.tar
data5.bin
bandit12@bandit:/tmp/trungpq$ file data5.bin
data5.bin: POSIX tar archive (GNU)
```
Lặp lại quá trình trên vài lần, ta sẽ ra được password
```bash
bandit12@bandit:/tmp/trungpq$ tar -xvf data5.bin
data6.bin
bandit12@bandit:/tmp/trungpq$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/trungpq$ tar -xvf data6.bin
data8.bin
bandit12@bandit:/tmp/trungpq$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Oct  5 06:19:20 2023, max compression, from Unix, original size modulo 2^32 49
bandit12@bandit:/tmp/trungpq$ mv data8.bin data8.gz
bandit12@bandit:/tmp/trungpq$ gzip -d data8.gz
bandit12@bandit:/tmp/trungpq$ ls
data5.bin  data6.bin  data8  data.tar
bandit12@bandit:/tmp/trungpq$ cat data8
The password is wbWdlBxEir4CaE8LaPhauuOo6pwRmrDw
```

### Level 13 → Level 14
Des: https://overthewire.org/wargames/bandit/bandit14.html

Ở đây, ta có private key để ssh vào level tiếp theo. Thử với `ssh -i`
```bash
bandit13@bandit:~$ ssh -i sshkey.private bandit14@localhost -p 2220
...
bandit14@bandit:~$
```
Ta đã thành công vào được level tiếp theo. Giờ chỉ việc lấy pass ở nơi trong đề bài.
```bash
bandit14@bandit:~$ cat  /etc/bandit_pass/bandit14
fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq
```

### Level 14 → Level 15
Des: https://overthewire.org/wargames/bandit/bandit15.html

Đơn giản chỉ là nộp pass vào cổng 30000. Mình đã thử với các giao thức khác nhau và kết quả là telnet

```bash
bandit14@bandit:~$ telnet localhost 30000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq
Correct!
jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt

Connection closed by foreign host.
```

### Level 15 → Level 16
Des: https://overthewire.org/wargames/bandit/bandit16.html

Tham khảo: https://superuser.com/questions/346958/can-the-telnet-or-netcat-clients-communicate-over-ssl

Mình sẽ sử dụng openssl để làm bài này:
```bash
bandit15@bandit:~$ openssl s_client -connect localhost:30001
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify error:num=10:certificate has expired
notAfter=Dec  3 06:50:34 2023 GMT
verify return:1
depth=0 CN = localhost
notAfter=Dec  3 06:50:34 2023 GMT
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA1
   v:NotBefore: Dec  3 06:49:34 2023 GMT; NotAfter: Dec  3 06:50:34 2023 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIEC4dflDANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMxMjAzMDY0OTM0WhcNMjMxMjAzMDY1MDM0WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
RDF2WJWBHTE6ARViD2ueomLlpTgugpreN7V8GuSIVhRjGdXuPAeydepyC1Jqs4Zk
iU5YwlsTikQgdQnO4tJYcZ43UHcGH67wgeQj11GVa7dNF2Ys2P27rjwSnK9KUgue
aWCwf0/glr1LSMPQQfIwXxitApsCLWT/woqMr4aBOueuUzOHl385J+pjM53mc8bL
/PfznNS3QDaRV/cpjgy9b5izf9a9qJnNpMAPRzYu+P1oglJmDvudVvjiTYLG5iOn
W/I75LHLN4hgl8ZEaSBwgaQ7N3CFHIV0s/Xwi630bK8R4HuTK+Gl3MAkTsQdqDZ/
ZSmZVmQYk9ZSpVFDWEN/AgMBAAGjZTBjMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDBL
BglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0ZWQgYnkgTmNhdC4g
U2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3DQEBBQUAA4IBAQB9
N6B6a+8AOUC0MudWFfz+Gm1h+OCpXWHjsbpBh9KI7LXkRnmo59hkNvoLvtPkGxDx
4v7dS+os6jR/lbjisAzUxEscxfRNTvVTgri1sHfp3V8EBFQM8gXe38qXzJ7+jgU7
QL7V7xHUTlK6lgI6U+1owOoDT3B9x3dwdhxDWnHoyYjG95ViAu2S9tFxN1dK3WCi
B/sogXltRDiD6NTVc03XWariMR80AbYxkKMsunBOLBhQkJhoXtF7Za4+4BhWozGm
RmYnE0xrknl36emGbnymYbloP2xfoZQuKhQ/7LW12YRr0zWG+ImMww2lfo/HKXEd
NSegczVdQu33PBmObo7B
-----END CERTIFICATE-----
subject=CN = localhost
issuer=CN = localhost
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1339 bytes and written 373 bytes
Verification error: certificate has expired
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 10 (certificate has expired)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 39C974D11291A75E282E2C67D3CF3CDCBFCE56C5D704A0AC6567F06697041ACC
    Session-ID-ctx:
    Resumption PSK: FBD8F5CF8D9C8390D2A20841003F1A07149CDB9AA5AD95EB95CAC2F103C6CC6244896FC4A3D458B00BCE33396FA22554
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 2b fe 06 2e 0d 50 02 75-90 df a8 0d 13 ec 47 37   +....P.u......G7
    0010 - 27 8a fc e9 08 94 bb 6f-10 d9 39 e7 44 88 ac e3   '......o..9.D...
    0020 - 76 31 ad 49 c5 6c ab cb-74 6d bd 87 5d 2a 68 87   v1.I.l..tm..]*h.
    0030 - a4 ad b5 3a cb 02 04 4c-40 e3 12 9d ce 8a 87 52   ...:...L@......R
    0040 - a7 4e 5b 6b 9d ef 23 a2-ac 72 f6 08 b6 3d 69 1a   .N[k..#..r...=i.
    0050 - 5e 25 74 56 f1 97 42 3a-0d 49 89 bd 03 67 f7 fc   ^%tV..B:.I...g..
    0060 - 12 7d 70 29 4f 81 3d 91-46 00 a0 b2 e0 62 8d 41   .}p)O.=.F....b.A
    0070 - ed f1 a5 54 82 4a 82 05-71 f4 18 a0 51 3c bb 4f   ...T.J..q...Q<.O
    0080 - 65 90 cd a0 da 78 c2 b9-ae d9 56 1c da fc 14 d5   e....x....V.....
    0090 - 7b 5e ec 5b f5 f7 3b a3-8a 42 0e 8f 6d 51 71 c9   {^.[..;..B..mQq.
    00a0 - a8 77 8c ba bd 49 25 22-42 88 e8 df 39 65 56 b0   .w...I%"B...9eV.
    00b0 - 8e 47 e3 d4 d1 2e b5 b6-ab 01 db 32 4d bc b9 ba   .G.........2M...

    Start Time: 1701663067
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 55EA1CBC9B429CA2CB459932D5D79A697869D55CE2540BC2A88AD517C847084A
    Session-ID-ctx:
    Resumption PSK: C4F6A973A6FDD498FBBC76315ECE1857AB848DAC31C71E8C0CAA8563B3CBB0D23D8DAB0B1A812C8AF7070BB454C75236
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 2b fe 06 2e 0d 50 02 75-90 df a8 0d 13 ec 47 37   +....P.u......G7
    0010 - 98 62 50 a1 e2 fa 61 63-70 cf 30 7a d9 22 92 f6   .bP...acp.0z."..
    0020 - 0c c0 27 1a e9 23 14 41-52 f2 e7 d0 f3 b4 58 5d   ..'..#.AR.....X]
    0030 - c8 7a 27 20 d8 69 79 4b-5e c5 1e 50 55 d2 31 30   .z' .iyK^..PU.10
    0040 - fe b2 a9 f0 d1 eb c5 fb-fc c1 b2 be b4 7d 89 01   .............}..
    0050 - ad 53 e7 72 01 2f 35 7f-e4 4e fd 73 5e 17 cb a0   .S.r./5..N.s^...
    0060 - 6e f6 e1 5d af f7 80 b5-76 9b 6a a1 95 9a 37 db   n..]....v.j...7.
    0070 - e9 4f bb 07 72 9a d5 93-4a a1 8c ad 49 4e 9a 6d   .O..r...J...IN.m
    0080 - df 38 af 62 3a da 70 4f-e1 f8 94 dd e5 61 cb f7   .8.b:.pO.....a..
    0090 - ca cf e5 c2 92 2a b4 0c-71 31 f4 58 23 b2 85 34   .....*..q1.X#..4
    00a0 - fd ee cf 45 e2 b0 b1 b5-5e 84 14 e2 29 cb c9 0a   ...E....^...)...
    00b0 - 5a a3 3c 52 3f 48 6d 2a-55 97 c8 88 6e f0 11 d1   Z.<R?Hm*U...n...
    00c0 - 43 e9 1e 5e d6 41 4c a3-57 65 19 87 cd 73 3e 16   C..^.AL.We...s>.

    Start Time: 1701663067
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
Correct!
JQttfApK4SeyHwDlI9SXGR50qclOAil1

closed
```



### Level 16 → Level 17
Des: https://overthewire.org/wargames/bandit/bandit17.html

Mình sẽ sử dụng `nmap -sV -p` để quét các cổng
```bash
bandit16@bandit:~$ nmap -sV -p 31000-32000 localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-04 04:22 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31790-TCP:V=7.80%T=SSL%I=7%D=12/4%Time=656D5423%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20cu
SF:rrent\x20password\n")%r(GetRequest,31,"Wrong!\x20Please\x20enter\x20the
SF:\x20correct\x20current\x20password\n")%r(HTTPOptions,31,"Wrong!\x20Plea
SF:se\x20enter\x20the\x20correct\x20current\x20password\n")%r(RTSPRequest,
SF:31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20password\
SF:n")%r(Help,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x
SF:20password\n")%r(SSLSessionReq,31,"Wrong!\x20Please\x20enter\x20the\x20
SF:correct\x20current\x20password\n")%r(TerminalServerCookie,31,"Wrong!\x2
SF:0Please\x20enter\x20the\x20correct\x20current\x20password\n")%r(TLSSess
SF:ionReq,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x20pa
SF:ssword\n")%r(Kerberos,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x
SF:20current\x20password\n")%r(FourOhFourRequest,31,"Wrong!\x20Please\x20e
SF:nter\x20the\x20correct\x20current\x20password\n")%r(LPDString,31,"Wrong
SF:!\x20Please\x20enter\x20the\x20correct\x20current\x20password\n")%r(LDA
SF:PSearchReq,31,"Wrong!\x20Please\x20enter\x20the\x20correct\x20current\x
SF:20password\n")%r(SIPOptions,31,"Wrong!\x20Please\x20enter\x20the\x20cor
SF:rect\x20current\x20password\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.34 seconds
```

Dựa vào kết quả nmap có thể nhận ra port mình cần là 31790. Kết nôi tới, mình ra được private ssh key của level tiếp theo
```bash
bandit16@bandit:~$ openssl s_client -connect localhost:31790
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify error:num=10:certificate has expired
notAfter=Dec  3 06:50:34 2023 GMT
verify return:1
depth=0 CN = localhost
notAfter=Dec  3 06:50:34 2023 GMT
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA1
   v:NotBefore: Dec  3 06:49:34 2023 GMT; NotAfter: Dec  3 06:50:34 2023 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIEMeSI+jANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMxMjAzMDY0OTM0WhcNMjMxMjAzMDY1MDM0WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9
4osQqA7RK75mD9eFboi2lArOz/JWq4YskGwdTqPtDl/BOYRaxHziLSY1jv0e1/j9
5e7BVeF8ds1ycGA+YFMXD/BTtZpprTqS+79bN1T+zbHOVoH4NvwG4q6lSzvM4CNW
eRko6lkoPtpKN4y7Ft8oMA6DVR06ld9C2BrEv9+UF9MAdRt5xvYXydk5GAJEdcyy
XnLD7dt+2PZJs2NLrPlVJnt3BBDPd4JSsTD6lm2cFF410xxLhqbmGvpcblG3HSRe
NxwBYdYx6Y2b2n7xNkwmTkMcwr49TTkvBBALWC6iJYQIS8LMLxq6C04/txr/ZkBZ
OpjLlfpKSkAv+NiFKP2/AgMBAAGjZTBjMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDBL
BglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0ZWQgYnkgTmNhdC4g
U2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3DQEBBQUAA4IBAQBZ
WQzYWksvvHPwQfNclAgFNteiBQkrCqEcijkCv91Neabf/Z/y2WsZUre2IKX3tHm/
ghNsuS+PoS8safuR7quE8+jRjKvGh6aqtW9eCPkHUBc9Y9s/9+b+YJniNlHwashu
PmwqWGCrH7I4IsxkTgO3ZvP136tkkrdnCWlEhuqShpyWrp3ATYUSZS7Jv/NNc83R
5pYcfGtJIoE4PDc1yS0qfVVkgM///EAvY4UFBo/lQ1GMGe0qv5ZlJX9qCMpLKms9
5JkBFHPbxey0ZI1yP0LcDQqnpAZkacwRBr3Hrloo6uLkSzOPiBUN3/eoERiUx+7s
X6jUzug8v7AVfli/Jdkh
-----END CERTIFICATE-----
subject=CN = localhost
issuer=CN = localhost
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1339 bytes and written 373 bytes
Verification error: certificate has expired
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 10 (certificate has expired)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 056B81B396EE5171A2E5C48F222DE5E81EDEB4D87B9838BF0BC134F5FA9A749E
    Session-ID-ctx:
    Resumption PSK: 0528B3D8C9F1F6D2A934CEA0182E23BF4881D1F84D19F9D4A9F9B1DEA368F35F2A0640F5DFB2E913B6B8EF338F93565F
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 50 21 ee 56 fb ef ef f3-18 f4 81 7b 6c cc d6 45   P!.V.......{l..E
    0010 - 67 b1 0e 5e 30 c4 9a 68-d8 04 aa 94 62 f0 35 4a   g..^0..h....b.5J
    0020 - ab d4 ab ad ca e6 b8 88-f5 3e 00 52 a3 af ca 4a   .........>.R...J
    0030 - b2 e0 aa 34 32 ae 91 2f-ef d0 f8 9e 02 d2 9d 50   ...42../.......P
    0040 - b9 c6 e0 0e ce c8 fb 62-a2 d2 8c e7 45 5b 4f 20   .......b....E[O
    0050 - 49 aa 02 b7 a9 27 16 5d-2d df b4 d1 a1 5b a9 b7   I....'.]-....[..
    0060 - fb 95 ef a9 40 69 8c f3-ce 76 0f 8e 83 ab 12 61   ....@i...v.....a
    0070 - 30 88 dc 2e b3 49 a7 4c-63 64 3f 73 b2 a6 a3 78   0....I.Lcd?s...x
    0080 - b1 80 50 71 a4 eb 21 f6-ca 10 3b 9b 3e 26 59 5c   ..Pq..!...;.>&Y\
    0090 - 34 22 27 2b e5 ba 3b 62-ce 13 11 b7 27 4e cf bb   4"'+..;b....'N..
    00a0 - c5 29 3b 19 d4 a4 d9 4c-8a e6 f1 bc 15 ae 5c 84   .);....L......\.
    00b0 - 9b 06 4c 12 4d 9d 68 b1-04 74 9e a9 ff c3 47 0c   ..L.M.h..t....G.
    00c0 - 69 9d 3c 7b 0a 86 bd d1-14 20 6b ce a2 62 7e f1   i.<{..... k..b~.

    Start Time: 1701663430
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 00A184027879E6EB9311FE56AB32D9D929B9D7FCA87D11BE95E4873CE517FB40
    Session-ID-ctx:
    Resumption PSK: 0B6A40FA38CC08F3DB5C2F96D79818CC9F7E553A611B314336844D726665BAECE061BD310340F43F4DE86E51470350B5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 50 21 ee 56 fb ef ef f3-18 f4 81 7b 6c cc d6 45   P!.V.......{l..E
    0010 - 86 80 f8 a3 70 bf 75 33-eb e2 4b ac d8 b0 eb b8   ....p.u3..K.....
    0020 - 44 3a d3 76 82 57 ab 3d-b8 5f 2e 9e 05 3c bb 63   D:.v.W.=._...<.c
    0030 - 1a 45 af fe 0a 89 98 19-6b de ee eb 23 a9 4d f1   .E......k...#.M.
    0040 - e2 a6 d4 69 11 28 35 57-de 39 19 80 f0 ac 22 ed   ...i.(5W.9....".
    0050 - f0 f4 2a ec d9 ad e9 5e-78 7f a0 8b 64 29 ce 0a   ..*....^x...d)..
    0060 - cf 7d 15 3a 0d 67 f9 ae-cc 2d 82 7b 66 7a 3d 4d   .}.:.g...-.{fz=M
    0070 - 29 c9 0a d6 f8 83 7d 3c-17 de b5 33 f2 2f 8d 1c   ).....}<...3./..
    0080 - eb ee 98 19 62 08 6e 20-79 d1 a1 65 be d1 a5 45   ....b.n y..e...E
    0090 - f2 64 23 bc b0 06 43 df-e5 06 15 66 2e bc 7c a5   .d#...C....f..|.
    00a0 - ed 41 9c 7c 87 87 d7 ac-a0 7a 7d d0 2e ea c3 c9   .A.|.....z}.....
    00b0 - 0f e3 84 41 13 27 32 b8-92 a6 5c c0 a8 97 52 b1   ...A.'2...\...R.
    00c0 - c8 31 9b 1d f2 1a 0f 93-c2 19 93 31 d5 87 65 f1   .1.........1..e.

    Start Time: 1701663430
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
JQttfApK4SeyHwDlI9SXGR50qclOAil1
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed
```
Do thư mục hiện tại không được phép ghi gì nên mình sẽ lưu private key này vào tmp và ssh tới level tiếp theo
```bash
bandit16@bandit:~$ vi /tmp/key.private
bandit16@bandit:~$ ssh -i /tmp/key.private bandit17@localhost
...
Permissions 0664 for '/tmp/key.private' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/tmp/key.private": bad permissions
```
Lúc này sẽ xảy ra lỗi như vậy. Mình thử `chmod 400` cho key.private và ssh thành công
```bash
bandit16@bandit:~$ chmod 400 /tmp/key.private
bandit16@bandit:~$ ssh -i /tmp/key.private bandit17@localhost -p 2220
...
bandit17@bandit:~$
```

Giống như level nào đó, mình có thể lấy pass bằng cách 
```bash
bandit17@bandit:~$ cat /etc/bandit_pass/bandit17
VwOSWtCA7lRKkTfbr2IDh6awj9RNZM5e
```

### Level 17 → Level 18
Des: https://overthewire.org/wargames/bandit/bandit18.html

Sử dụng `diff`, ta ra được password:
```bash
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< p6ggwdNHncnmCNxuAt0KtKVq185ZU7AW
---
> hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg
```

### Level 18 → Level 19
Des: https://overthewire.org/wargames/bandit/bandit19.html

Ở challenge này, khi ta ssh tới sẽ bị log out ra. Đề bài nói do file .bashrc đã được sửa đổi (.bashrc là tệp cấu hình cho môi trường dòng lệnh Bash của một người dùng trên hệ thống Linux hoặc Unix)

Để giải quyết vấn đề, ta có thể không sử dụng bash để ssh tới mà sử dụng một shell khác với tham số -t khi ssh.
`ssh bandit18@bandit.labs.overthewire.org -p 2220 -t "/bin/sh"`

Và ta có được pass
```shell
$ cat readme
awhqfNnAbc1naukrpqDYcF95h7HoMTrC
```

### Level 19 → Level 20
Des: https://overthewire.org/wargames/bandit/bandit20.html

Này là minh họa cho setuid. Trong linux, nó cho phép một tệp thực thi chạy với quyền của người sở hữu (owner) của tệp thay vì với quyền của người dùng thực hiện tệp. Khi `ls -l` sẽ thấy có chữ "s"

File `bandit20-do` sẽ giúp chúng ta thực thi lệnh dưới quyền bandit20. Lấy password bằng cách sau:

```bash
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
VxCazJaVykI6W36BkBU0mJTCM8rR95XT
```

### Level 20 → Level 21
Des: https://overthewire.org/wargames/bandit/bandit21.html

File "suconnect" sẽ kết nối tới cổng người dùng nhập và lấy dữ liệu trả về. Nếu trùng với password của level trước thì sẽ trả về password của level sau

Vậy ta có thể tạo 1 server mà khi kết nối tới sẽ trả về password cũ. Các bạn có thể viết code hoặc sử dụng netcat như sau:
```bash
bandit20@bandit:~$ echo "VxCazJaVykI6W36BkBU0mJTCM8rR95XT" | nc -nvlp 2706 &
[1] 2714766
```

Giờ chỉ cần chạy file
```bash
bandit20@bandit:~$ ./suconnect 2706
Connection received on 127.0.0.1 41506
Read: VxCazJaVykI6W36BkBU0mJTCM8rR95XT
Password matches, sending next password
NvEJF7oVjkddltPSrdKEFOllh9V1IBcq
[1]+  Done                    echo "VxCazJaVykI6W36BkBU0mJTCM8rR95XT" | nc -nvlp 2706
```


### Level 21 → Level 22
Des: https://overthewire.org/wargames/bandit/bandit22.html

Thử `cd` vào folder cron.d ta có các file
```bash
bandit21@bandit:~$ cd /etc/cron.d/
bandit21@bandit:/etc/cron.d$ ls
cronjob_bandit15_root  cronjob_bandit22  cronjob_bandit24       e2scrub_all  sysstat
cronjob_bandit17_root  cronjob_bandit23  cronjob_bandit25_root  otw-tmp-dir
```
Mở file có chữ bandit22, ta thấy công việc đc thực hiện khi chạy level.
```bash
bandit21@bandit:/etc/cron.d$ cat cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

Thử xem file xem điều gì được thực thi, mình tìm đc nơi lưu password:
```bash
bandit21@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
Việc còn lại chỉ là lấy pass
```bash
bandit21@bandit:/etc/cron.d$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff
```

### Level 22 → Level 23
Des: https://overthewire.org/wargames/bandit/bandit23.html

Tương tự level trước, ở đây mình có nội dung file "cronjob_bandit23.sh" như sau
```bash
bandit22@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

Có thể thấy pass đc lưu vào file "/tmp/$mytarget" với `mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)`. Chúng ta hoàn toàn có thể tính được giá trị mytarget vì đã biết $myname là bandit23 bằng cách nhập vào terminal:
```bash
bandit22@bandit:/etc/cron.d$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
```

Cat để lấy password:
```bash
bandit22@bandit:/etc/cron.d$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
QYw0Y2aiA672PsMmh9puTQuhoz8SyR2G
```

### Level 23 → Level 24
Des: https://overthewire.org/wargames/bandit/bandit24.html

Cũng tương tự, đây là nội dung file "cronjob_bandit24.sh"
```bash
bandit23@bandit:/etc/cron.d$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

Script này đơn thuần là kiểm tra tất cả các file trong /var/spool/bandit24/foo và xóa các file có owner là bandit23. Tuy nhiên, trước khi xóa, nó lại thực thi file đó. Vì vậy, ta có thể viết script để lấy pass của bandit24. 

```bash
#!/bin/bash

cat /etc/bandit_pass/bandit24 > /tmp/trungpqt

```

Viết trong tmp và đáp nó vào trong thư mục "foo". Chúng ta sẽ ngồi chờ chương trình được thực thi và mở file trungpqt ra xem pass
```bash
bandit23@bandit:/var/spool/bandit24$ cp /tmp/payload.sh ./foo
bandit23@bandit:/var/spool/bandit24$ chmod 777 ./foo/payload.sh
bandit23@bandit:/var/spool/bandit24$ chmod 777 /tmp/trungpqt
bandit23@bandit:/var/spool/bandit24$ cat /tmp/trungpqt
VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar
```

### Level 24 → Level 25
Des: https://overthewire.org/wargames/bandit/bandit25.html

Đề bài yêu cầu kết nối tới cổng 30002. Chương trình sẽ bắt chúng ta nhập vào pass của bandit24 và 1 pincode gồm 4 chữ số. Ta có thể viết bashscript để thực hiện gen ra payload như sau
```bash
#!/bin/bash
for i in {0000..9999}
do
        echo "VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar $i"
done
```
Sau đó ta chạy lệnh:
```bash
bandit24@bandit:/tmp$ ./pass.sh | nc localhost 30002 | grep -v "Wrong"
I am the pincode checker for user bandit25. Please enter the password for user bandit24 and the secret pincode on a single line, separated by a space.
Correct!
The password of user bandit25 is p7TaowMYrmu23Ol8hiZh9UvD0O9hpx8d

Exiting.
```

Các bạn có thể viết code python pwntools nhưng nó sẽ rất lâu

### Level 25 → Level 26
Des: https://overthewire.org/wargames/bandit/bandit26.html

Ở đây, ta có được private key để ssh tới bandit26. Tuy nhiên, khi ssh tới thì bị diss lun
```bash
bandit25@bandit:~$ ssh -i bandit26.sshkey bandit26@localhost -p 2220
...
Connection to localhost closed.

```
Đọc kĩ lại đề bài, ở đây ta được biết bandit26 không dùng /bin/bash. Vậy nó dùng cái gì? Có thể kiểm tra bằng cách xem trong /etc/passwd
```bash
bandit25@bandit:~$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

Ở đây, ta thấy user này sử dụng /usr/bin/showtext. Thử đọc nội dung của nó
```bash
bandit25@bandit:~$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
```

Ta thấy nó thực hiện lệnh `more` để đọc file text.txt, khi đọc xong sẽ exit luôn. Điều thú vị ở lệnh `more` là nếu màn hình không đủ lớn để đọc hết 1 đoạn text thì nó sẽ cho mình hiển thị dần chứ không như lệnh `cat`. Trong lúc như vậy, ta có thể gọi ra shell để lấy được password.

Vậy đầu tiên là ta phải thu nhỏ màn hình terminal lại hết cỡ có thể, rồi sau đó ssh. Ta sẽ vào được `more`. Khi bạn đã không bị diss, hãy ấn nút `V`. Khi ấn `V` trong `more`, ta sẽ được nhảy sang vim

Khi này, ta có thể lấy pass bằng cách gõ lệnh sau trong vim
```bash
:e /etc/bandit_pass/bandit26
```

hoặc ta có thể làm như sau để lấy được shell của bandit26:
```bash
:set shell=/bin/bash
:shell
```
Từ 2 cách trên đều sẽ lấy được pass là c7GvcKlw9mC7aUQaPx7nwFstuAIBw1o1

### Level 26 → Level 27
Des: https://overthewire.org/wargames/bandit/bandit27.html

Này thì lại là setuid
```bash
bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
YnQpBuifNMas1hcUFk70ZmqkhUU2EuaS
```
### Level 27 → Level 28
Des: https://overthewire.org/wargames/bandit/bandit28.html

Như đề bài chỉ, đầu tiên ta `git clone` repo qua cổng 2220
```bash
bandit27@bandit:/tmp$ git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
Cloning into 'repo'...
The authenticity of host '[localhost]:2220 ([127.0.0.1]:2220)' can't be established.
ED25519 key fingerprint is SHA256:C2ihUBV7ihnV1wUXRb4RrEcLfXC5CXlhmAAM/urerLY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/bandit27/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/home/bandit27/.ssh/known_hosts).
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit27-git@localhost's password:
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (3/3), done.
```

Mở repo và đọc file, ta ra password
```bash
bandit27@bandit:/tmp$ cd repo
bandit27@bandit:/tmp/repo$ ls
README
bandit27@bandit:/tmp/repo$ cat README
The password to the next level is: AVanL161y9rsbcJIsFHuw35rjaOM19nR
```

### Level 28 → Level 29
Des: https://overthewire.org/wargames/bandit/bandit29.html

Tương tự level trước, ta git clone repo về và đọc file. Tuy nhiên lần này thì không có luôn password

```bash
bandit28@bandit:/tmp/rep$ cat README.md
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx

```

Mình sẽ thử dùng `git log -p` để xem lịch sử commit
```bash
bandit28@bandit:/tmp/rep$ git log -p
commit 14f754b3ba6531a2b89df6ccae6446e8969a41f3 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    fix info leak

diff --git a/README.md b/README.md
index b302105..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials

 - username: bandit29
-- password: tQKvmcwNYcFS6vmPHIUSI3ShmsrQZK8S
+- password: xxxxxxxxxx


commit f08b9cc63fa1a4602fb065257633c2dae6e5651b
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Oct 5 06:19:41 2023 +0000

    add missing data

diff --git a/README.md b/README.md
```

Và ta đã thấy password

### Level 29 → Level 30
Des: https://overthewire.org/wargames/bandit/bandit30.html

Tương tự, nội dung file README lần này là
```bash
bandit29@bandit:/tmp/reps$ cat README.md
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```

