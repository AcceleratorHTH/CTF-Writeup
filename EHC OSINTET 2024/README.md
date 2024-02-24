# EHC OSINTET 2024

## **Author:**

* Pham Quoc Trung

## **Used Tools:**

* Brain and Google
* OSINT Framework

## Problem Solving

#### Những step đầu

Đầu tiên thì đây là challenge của chúng ta: [link](https://www.facebook.com/ehc.fptu/posts/pfbid046XSvrZpumgWyjaS221nv1JYx5WQYA6YikkSiE4EqvNbC7x1hdnkk8oqWtHLpBHAl?\_\_cft\_\_\[0]=AZW9MNDvEwn6NnRXFI-7vbUPXtPSYIbYFO2TF-jeSFXmkdxdVI7e82paHYxFFV2eGXYrfgNYeDx0Z3o5-pAjfw2mntyzv9j0Z6\_UqEqlztHvXr20aJzsPuzdg9qCClneSN9w\_D8h\_ADdHzk8DGkeTHVIG56ROdKQyrl62oNzycTse\_UuANcPZAuPyGcAXuYLhars5bXPkVXQNhw7e2dq7vx8O97\_ndT9Ojbs2Gp7YlOqzw&\_\_tn\_\_=%2CO%2CP-R)

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Ở đây trên ảnh mình thấy có một dòng chữ là `@m1ssgr4ndvi3tnam`.  Mình thử search username này trên một số nền tảng phổ biến như facebook, instagram, x, ... và kết quả là mình có một profile trên Pinterest ([link](https://www.pinterest.com/m1ssgr4ndvi3tnam/))

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Có 2 ảnh trên trang Pinterest này. Một ảnh là ảnh đã được đăng trên facebook và có vẻ không có gì mới

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

Đến với ảnh thứ hai:

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Mình đã thử tìm các thông tin liên quan tới id `MarkXuanDepTrai` kia nhưng có vẻ không có gì. Ở đây mình để ý ở comment có một user tên là `Nhi3n` có profile Pinterest như sau:

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Đoạn này thì mình éo search ra được gì nên mình thử tìm thêm về cụm `@m1ssgr4ndvi3tnam` và khi tìm với từ khóa `m1ssgr4nd` trên Github, mình tìm được một repo như sau

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

#### Về trang Github

<figure><img src="../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Ở đây có một số ảnh. Mình nghĩ là có steganography, tuy nhiên mình không tìm được gì ngoài một số câu văn vẻ ở trong ảnh `backgroundw2.png`

<figure><img src="../.gitbook/assets/Screenshot 2024-02-13 142724 (2).png" alt=""><figcaption></figcaption></figure>

Thử xem profile github của repo này

<figure><img src="../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

Nhìn cái tên `Nhi3n` thì có vẻ đây cũng chính là thứ mình cần tìm ra sau cái Pinterest kia. Trong đoạn giới thiệu cũng có một dãy số đáng ngờ `387, 521, 63, 789, 245, 432, 78, 605, 124, 356, 892`. Ở đây khi mình xem file README.md thì mình thấy có một vài lịch sử commit. Cụ thể:

<figure><img src="../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

Với commit này thì mình thấy trước đó dãy số kia có giá trị là `19 14 30 50 92 55 73 88 49 31 10`. Mình có thử XOR xủng modulo các thứ 2 dãy này cơ mà có vẻ không cao siêu đến vậy. Sau cùng thì khi đọc markdown của README.md, mình thấy có một số dòng có link dạng như này

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

Có 11 dòng như vậy, và số của các dòng này cũng đều tồn tại trong list `387, 521, 63, 789, 245, 432, 78, 605, 124, 356, 892`. Mình thử lấy kí tự cuối cùng của từng link theo thứ tự trong list thì ra được chuỗi `J6gDm5yvYy0`. Thử cho vào Youtube và mình được video sau: [link](https://www.youtube.com/watch?v=J6gDm5yvYy0)

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

Cả video chỉ có cái tên `Telsom TWC-1150` là được thêm vô. Tra google thì mình thấy nó là một mẫu điện thoại&#x20;

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Mình chưa thấy có gì lắm, nên quay lại xem các commit khác

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Link màu xanh chỉ là một link nhạc ([link](https://www.youtube.com/watch?v=WZou-8HwNHI)), không có gì thú vị. Đối với link màu đỏ thì có vẻ nó đã bị mã hóa đoạn đầu. Mình thử đáp vào Quipquip

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

Nhìn sơ qua thì mọi kết quả đều có chữ `google`. Dựa vào số các kí tự, mình đoán đây là trang `sites.google.com`. Thử ghép vào và mình ra được trang sau: [link](https://sites.google.com/view/m1ssgr4ndvietnam/main)

<figure><img src="../.gitbook/assets/Screenshot 2024-02-25 013900.png" alt=""><figcaption></figcaption></figure>

Ở cuối trang có một số thông tin như sau

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Cái Pinterest thì mình đã thấy rồi. Ở đây có thêm về X và Email.&#x20;

#### Về phần X

Ở đây mình có link X: [link](https://twitter.com/m1ssgr4ndvi3tna)

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

Ở đây mình có 2 ảnh, một ảnh nền và một ảnh trong post

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

Với đoạn hex ở ảnh đầu thì sau khi decode, mình ra được cụm `ILoveHimSoMuch<3`. Có vẻ không để làm gì.

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Ở ảnh sau thì mình thấy có một đoạn binary. Một số chỗ đã bị che mất, tuy nhiên sau khi so sánh với phần binary ở trong ảnh bìa thì mình thấy nó chính là phần bị che mất. Mình viết được cụm này

```
0000111001000011011000001100110000111001000011010000001110000000110010000011001100001110010000111000000011010000001100010000110010000011011000001101000001100001000000000000111001000110110000110011000111001000110100000111000000110010000110011000111001000111000000110100000110001000110010000110110000110100001100001000000000001000111001000110110000110011000100011100100011011000011001100001110010001101100001100100011100100011011000011000011100100011011000000011100100011011000001110010001100000111001000100011100100001110000011
```

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

Tuy nhiên khi decode với đủ kiểu byte length thì mình chả ra cái mẹ gì. Nhớ đến một challenge mình từng chơi trên page Whitehat, mình nghĩ chỉ cần quan tâm tới các dòng trước dòng bị che. Nghĩa là chỉ còn như sau

```
0000111001000011011000001100110000111001000011010000001110000000110010000011001100001110010000111000000011010000001100010000110010000011011000001101000001100001
```

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Với Byte Length là 10 thì mình ra được chuỗi `963948239841264a`. Thử tìm kiếm trên một số trang thì mình ra được một trang facebook sau: [link](https://www.facebook.com/963948239841264a)

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

Có vài bài viết, nhưng mấu chốt là đây

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

Dựa vào comment, mình dễ dàng nhận ra thông điệp là `_FROM`.

#### Về email

Chưa thấy gì thêm ở facebook nên mình quay về vụ email. Có thể thấy là từ trong sites tới X, Facebook đều có dòng kiểu `Contact email ...`. Mình thử mò một vài email và có cái như sau hiện lên thông tin

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

Thử gửi một email bất kì tới đó và mình nhận được phản hồi như sau

> Vào thời điểm mình viết wu thì cái mail ml này đã éo phản hồi nữa mà mình lỡ lọc email rồi nên mượn tạm ảnh người khác

<figure><img src="../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Ở đây mình có được part1 của flag là `twrLwcA!J0}bH0b2C0*`. Thử giải mã bằng CyberChef

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Và part 1 của flag chính là `EHC{H4pPy_N3w_Y3ar_`.

#### Về kênh Discord

<figure><img src="../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Ở đây sau khi join server discord, mình thấy có 2 con bot là `Inv1s1bl3` và `Miss Grand`. Mình thử chat cho chúng. Với con `Inv1s1bl3` thì đây là thứ có vẻ có ích duy nhất

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

Có vẻ nó gợi ý mình sử dụng loại mật mã nào đó. Đến với con bot `Miss Grand`, đây là con bot sẽ đưa ra captcha cho người dùng và bắt người dùng trả lời. Đây là khi mình trả lời sai

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Còn đây là khi mình trả lời đúng hết

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Vậy là mình có 2 link cần phải giải mã. Đoạn này thì mình cũng phải nghĩ một hồi. Tuy nhiên, dựa trên việc đoạn đầu mình đoán ngay được là `https://www.youtube.com/watch?v=`, và nhận thấy các kí tự giống nhau khi mã hóa lại khác nhau, cũng như đây là osintet, sẽ không sử dụng các cipher quá lạ, mình đoán được đây là Vigenere Cipher. Do không biết `key` nên mình sẽ phải mò

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

Sau một hồi mò thì mình thấy `missg` sẽ ra được `https`. Từ đây, mình đoán ra key là `missgrand`

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

À đm cái này ra rickroll :v, đây mới đúng

<figure><img src="../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Đây là link youtube mình thu được: [link](https://www.youtube.com/watch?v=Fqo-vzP8aco)

<figure><img src="../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

Thử xem description của video này, mình có được part cuối của flag là `_2017}`.

<figure><img src="../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

#### Bonus

Ban đầu thì mình nghĩ là video này chỉ để lấy flag cuối. Tuy nhiên, khi đến đoạn bấm số điện thoại, mình cảm giác tiếng bấm và hành động của mấy bà chị này có vẻ không khớp cho lắm. Đó là ở phút 3:44

Mình thử search youtube với từ khóa `gọi điện đến số điện thoại ma ám` và ra được video gốc sau: [link](https://www.youtube.com/watch?v=vM-Qr0ykJJg)

<figure><img src="../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

Và đúng là video gốc không có tiếng gõ như vậy. Nhớ lại bên trên, mình có hint về cái điện thoại Telson TWC 1150, mình đoán có vẻ đây là một thông điệp dạng nào đó. Trước đây, mình có chơi một giải CTF cũng có kiểu tiếng như vậy, và mình nhận ra nó là **DTMF (dual tone multi-frequency)**&#x20;

<figure><img src="../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

Mình thử lấy ra đoạn sound bằng cách bỏ chữ `ube` khỏi link đi và sử dụng một trang DTMF Decoder bất kì

<figure><img src="../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

Mình ra được chuỗi là `944484455566688833`, cái này thì khá quen thuộc với mình. Mình sẽ decode nó luôn

<figure><img src="../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

Và mình ra được thêm 1 part của flag là `WITHLOVE`.

#### Quay lại google sites

Vì được biết là có 5 part của flag nên mình quay lại google sites xem có gì hay không. Vì đây là google sites, mình biết chức năng search của mỗi trang sẽ nằm ở `/search/<tentrang>`

<figure><img src="../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

Google sites nên chức năng tìm kiếm cũng khá giống google. Bằng cách tìm `*`, mình ra được toàn bộ page của web này

<figure><img src="../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

Thấy kết quả thứ hai có chữ `flag`, mình vào xem thử

<figure><img src="../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

Ở đây mình thấy có một list các tọa độ, mình sẽ thử tìm chúng trên Google Map

Mình tạo một sheet như sau

<figure><img src="../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

Vào Google Maps chọn Saved -> Maps -> Create Map

Import file xlsx trên vào với tùy chọn là Latitude, Longitude. Mình có được map như sau

<figure><img src="../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

Vậy là part còn lại của flag chính là `EHC`.

#### Tổng kết

Vậy là mình đã có 5 mảnh của flag lần lượt theo thứ tự mình tìm ra là `_FROM`, `EHC{H4pPy_N3w_Y3ar_`, `_2017`, `WITHLOVE` và `EHC`. Chắc đến đấy các bạn có thể dễ dàng ghép lại được rồi nhỉ?

FLAG: `EHC{H4pPy_N3w_Y3ar_FROMEHCWITHLOVE_2017}`



**© 2023,Pham Quoc Trung. All rights reserved.**
