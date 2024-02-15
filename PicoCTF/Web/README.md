# PicoCTF Web

## **PicoCTF**

## **WEB EXPLOITATION WRITEUP**

## **Author:**

* Pham Quoc Trung

## Problem Solving:

### GET aHEAD

#### Description:

Find the flag being held on this server to get ahead of the competition [http://mercury.picoctf.net:47967/](http://mercury.picoctf.net:47967/)

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

#### Solution:

Ở bài này khi nhìn vào request trên BurpSuite mỗi lúc ấn vào 2 nút để chọn màu, mình thấy nó chỉ khác nhau ở HTTP Request Method là chính

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Đầu tiên phải nói đến là có tất cả 9 loại request, get và post là 2 loại thông dụng được sử dụng nhiều.&#x20;

* GET: được sử dụng để lấy thông tin từ sever theo URI đã cung cấp.&#x20;
* HEAD: giống với GET nhưng response trả về không có body, chỉ có header&#x20;
* POST: gửi thông tin tới sever thông qua các biểu mẫu http( đăng kí chả hạn..)&#x20;
* PUT: ghi đè tất cả thông tin của đối tượng với những gì được gửi lên&#x20;
* PATCH: ghi đè các thông tin được thay đổi của đối tượng.&#x20;
* DELETE: xóa tài nguyên trên server.&#x20;
* CONNECT: thiết lập một kết nối tới server theo URI.&#x20;
* OPTIONS: mô tả các tùy chọn giao tiếp cho resource.&#x20;
* TRACE: thực hiện một bài test loop - back theo đường dẫn đến resource.

> Tìm hiểu thêm: [https://viblo.asia/p/cung-tim-hieu-ve-http-request-methods-djeZ1xBoKWz](https://viblo.asia/p/cung-tim-hieu-ve-http-request-methods-djeZ1xBoKWz)

Mình sẽ thử thay các Method khác nhau vào, và đây là kết quả khi dùng $$\text{HEAD}$$

<figure><img src="../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Flag: _picoCTF{r3j3ct\_th3\_du4l1ty\_cca66bd3}_

### Cookies

#### Description:

Who doesn't love cookies? Try to figure out the best one.&#x20;

[http://mercury.picoctf.net:27177/](http://mercury.picoctf.net:27177/)&#x20;

<figure><img src="../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

#### Solution:

Do có sẵn chữ trong thẻ input, mình thử nhập cái đó vào thì kết quả trả về như sau

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Khi mình thử nhập bất kì, ví dụ `flag`, kết quả trả về như sau

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Nhìn vào cookies, mình để ý ban đầu nó có giá trị `name = -1`. Tuy nhiên sau khi gửi `snickerdoodle`, nó đã được set thành 0

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Mình thử thay bằng 1, và mình thấy được 1 loại cookie khác

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Khả năng sẽ còn nhiều loại cookie khác nên mình sẽ sử dụng Intruder để thử các trường hợp và grep flag

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Với `name = 18`, mình đã có được flag

Flag: _picoCTF{3v3ry1\_l0v3s\_c00k135\_064663be}_

