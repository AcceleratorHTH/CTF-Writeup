# **WannaGame Championship 2023**

# **CRYPTOGRAPHY WRITEUP**

## **Author:**

- Pham Quoc Trung

## **Used Language:**

- Python3

## **Problem Solving**
### cossin
I here that one line crypto challenges are trending. Try this:

- chall.sage: `print((lambda x: (sin(x)*cos(x)).n(1337))(int.from_bytes(open("flag.txt", "rb").read(), "big")))`

NOTE: FLAG is a readable string

Attachment: *output.txt*
```
-0.485299053406871278251006491694722007834238650283783529182391610856900053091072342569384613414742720641855490790461240852899350288280072305993228008096260187870917816030712286113220053439434851762423438010136608133662561275124101194472809756885647907717262697745396526025380800595185118739690636922816074026435450112655435095006364390082673418410069153276551846375507805947540946003578965083647629783181
```
Với challenge này, flag được chuyển thành một số nguyên x rồi sau đó thực hiện tính sin x * cos x và trả về kết quả có 1337 chữ số thập phân. 

Ban đầu, mọi thứ có vẻ đơn giản khi áp hàm lượng giác vào sin(x)*cos(x) = 1/2 * sin(2*x). Khi đó, x sẽ bằng 1/2 * arcsin(2*kết quả). Tuy nhiên số này sẽ không đủ để khôi phục lại được đúng flag ban đầu.

Vì vậy, mình đã tìm được wu này: https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Tan. Nôm na là chúng ta sẽ sử dụng LLL để khôi phục. Giờ mình vẫn ngu lattice nên cứ đập code đã hiểu tính sau :v 

```python3
bits = 1337
t = (
    -0.485299053406871278251006491694722007834238650283783529182391610856900053091072342569384613414742720641855490790461240852899350288280072305993228008096260187870917816030712286113220053439434851762423438010136608133662561275124101194472809756885647907717262697745396526025380800595185118739690636922816074026435450112655435095006364390082673418410069153276551846375507805947540946003578965083647629783181
)
at = arcsin(2*t)
pin = pi.n(bits)

L = matrix(QQ, [[1, 0, 0], [at, 1, at], [pin, 0, pin]])
L[:, 0] *= 2**bits
L = L.LLL()
L[:, 0] /= 2**bits
print(L[0])
m = abs(round(L[0][-1]))
m = m //2
print(m)
print(1/2 * sin(2*m).n(bits))
print(t)
print(int(m).to_bytes((m.bit_length() + 7) // 8, "big"))
```
Và mình ra được kết quả
```
(-4236033959284229774157303269471835580651889509021336958830257893980283385270314406328155214739943353167615826659490/1635581762163556080294241261001682940030666867439890491155118001770564105982785320432573134068386821619116320799551639664529442180413849099719065212404931552657945409426238055584520966740116896632693534365218844505009117047712027310168190856606396053131704575033124096357496817899883985317067899195996608295589570286464156468159938868942417574847134095627432697584751042392969693879100945663823383168709, -1, 43899914522971839625017398818398634410935706342895429983904300843582088112487187936542803653307497469534683606248657704479171026948580220357667866435568628932319597610384426265140992786330348331299541284296114947872824977114915194998336914043314396251995271779766643476176586836663971338152179775552758172855971451237795394359354068728846465811543663514033872439031851485546345417245496862226239278571388715629363528236621501344292409812733296002127318905384326633197028171962825345389942818849548708683422280998520256/1635581762163556080294241261001682940030666867439890491155118001770564105982785320432573134068386821619116320799551639664529442180413849099719065212404931552657945409426238055584520966740116896632693534365218844505009117047712027310168190856606396053131704575033124096357496817899883985317067899195996608295589570286464156468159938868942417574847134095627432697584751042392969693879100945663823383168709)
13420275139562819491876648267068338866147900151069168750822206723521701909899833723013462046457430938047116652143997
-0.485299053406871278251006491694722007834238650283783529182391610856900053091072342569384613414742720641855490790461240852899350288280072305993228008096260187870917816030712286113220053439434851762423438010136608133662561275124101194472809756885647907717262697745396526025380800595185118739690636922816074026435450112655435095006364390082673418410069153276551846375507805947540946003578965083647629783181
-0.48529905340687127825100649169472200783423865028378352918239161085690005309107234256938461341474272064185549079046124085289935028828007230599322800809626018787091781603071228611322005343943485176242343801013660813366256127512410119447280975688564790771726269774539652602538080059518511873969063692281607402643545011265543509500636439008267341841006915327655184637550780594754094600357896508364762978318
b'W1{B4by_m4th_f0r_LLL_0dbb94edb18d7cba7b2bb20f9e}'
```

Flag: W1{B4by_m4th_f0r_LLL_0dbb94edb18d7cba7b2bb20f9e}

### Council of Sheep
The beauty of math is that it always tell the truth

Attachment: *the_council_of_sheep.tar.gz*

**Author:**
here is the solution for the council of sheep chall, but from what I heard, almost all teams abuse the bug in the chall , which can print flag with out passing any challenge ( that is my mistake lmao ) 🤣
```python3
from pwn import *
io = process(["python3", "server.py"])
# io = remote("157.245.147.89" , 20098)
sla = io.sendlineafter 
sa = io.sendafter 
sl = io.sendline 


def hamming_dst_num(a, b):
    return sum([1 if i == "1" else 0 for i in bin(a ^ b)[2:]])

def hamming_distance_list(a, b): #hamming distance, a and b are lists
    return sum([i != j for i, j in zip(a,b)])

def int2bool_arr(state, N): #N: length
    return [int(i) for i in bin(state)[2:].zfill(N)]


def bool_arr2int(arr):
    return int("".join("1" if i else "0" for i in arr), 2)

def gadget(idx, val):
    return f"( sheep[{idx}] == {val} )"

def gadget_of_state(state):
    return "( " + " and ".join([gadget(idx, i) for idx, i in enumerate(state)]) + " )"

def gadget_of_list_state(list_state):
    return "( " + " or ".join([gadget_of_state(i) for i in list_state]) + " )"



def creating_sequence(q, n, err): #q : number question, n : number of sheep
    sequence = []
    for i in range(2 ** q):
        condition = True 
        for j in sequence:
            if hamming_dst_num(i, j) <= err * 2 :
                condition = False
                break 
        if condition:
            sequence.append(i)
        
        if len(sequence) >= 2 ** n :
            print(f"create enough space for {2 ** n} with error {err}")
            break 
    return sequence

def nearest_neighbor(state, sequence_state):
    idx, ans = 0, 100
    numstate = bool_arr2int(state) 
    for i in sequence_state:
        if hamming_dst_num(numstate, i) < ans:
            idx = i
            ans = hamming_dst_num(numstate, i)
    return idx 


def solve_stage2(q, n, err, roundnum):
    questions = [[] for i in range(q)]
    sequence_state = creating_sequence(q, n, err)
    # print("finish generate sequence")
    for idx, state in enumerate(sequence_state): #idx is the state with n bits, state is the mapping state of idx with q bits
        arrstate = int2bool_arr(state, q)
        for i in range(q):  
            if arrstate[i]:
                questions[i].append(int2bool_arr(idx, n))
    
    for ROUND in range(roundnum):
        state = []
        io.recvuntil(f"ROUND".encode())
        for i in range(q):
            sla(b"question:\n", gadget_of_list_state(questions[i]).encode())
            msg = io.recvline(0).decode()
            if "Yes" == msg:
                state.append(1)
            else:
                state.append(0)
            print(f"done ask {i}-th question")
        ans = nearest_neighbor(state, sequence_state)
        ans = int2bool_arr(sequence_state.index(ans), n)
        sla(b"Who are them?\n", " ".join(str(int(i)) for i in ans).encode())
        # io.interactive()

# def cheating_stage1():
#     for i in range(10):
#         io.recvuntil(b"Who is guilty?\n")
#         ans = io.recvline(0)
#         io.sendline(ans)

graph = [[] for i in range(50)]
low = [None for i in range(50)]
num = [None for i in range(50)]

cnt = 0

wolves = []
def dfs(u, par):
    global cnt, wolves, graph
    cnt += 1 
    num[u] = cnt
    low[u] = cnt 
    for v in graph[u]:
        if v != par :
            if num[v] != -1:
                low[u] = min(low[u], num[v])
            else:
                dfs(v, u)
                low[u] = min(low[u], low[v])
                if num[v] == low[v]:
                    # print(f"{u} {v}")
                    if not (v in wolves):
                        wolves.append(v)
                    if not (u in wolves):
                        wolves.append(u)



def solve_stage1(roundnum):
    global wolves, low, num, graph, cnt
    io.recvuntil(b"STAGE 1\n")
    # io.interactive()
    for rnd in range(roundnum):
        io.recvuntil(b"ROUND")
        io.recvline(0)
        # io.interactive()
        #reset state
        for i in range(50):
            graph[i] = []
        wolves = []
        num = [-1 for i in range(50)]
        low = [-1 for i in range(50)]
        cnt = 0

        for i in range(50):
            io.recvuntil(b"trust: ")
            graph[i] = eval(io.recvline(0).decode())
        dfs(0, -1)
        sla(b"guilty?\n", str(wolves).encode())
    pass



def solve():
    solve_stage1(50)
    print("STAGE 1 complete")
    solve_stage2(11, 5, 1, 20)
    print("DONE 1")
    solve_stage2(15, 7, 2, 20)
    print("STAGE 2 complete")
    pass


solve()

io.interactive()
```

![image](https://github.com/AcceleratorHTH/CTF-Writeup/assets/86862725/ba0ddb6c-3398-4c30-b2f0-e76ecae6302e)


explain : the first stage is actually finding bridge problem, it can be solved using tarjan algorithm, and the idea for the second one is using error correcting code, the idea for the 2nd stage is actually taken from 1 challenge in wmctf 2022 (nanoDiamond). You can read the idea to solve in here : https://imp.ress.me/blog/2022-08-22/wmctf-2022#nanodiamond---rev- 



### Among SUS
Fact: Among SUS is the sussier version of Among US...

`nc 157.245.147.89 12001`

Attachment: *public.zip*

**Author:**
https://github.com/viensea1106/my-ctf-challenges/tree/main/wannagame-championship-2023/AmongSUS

- idk whats the intended, but we just received the player info then got a task, iterated over players and generated the key, then check if the mac decrypt works with that key, if it does not its not the impostor, else it is the impostor and we can send the server that name. ah that's the unintended

- oh that is unintended, so sad, when I originally created this challenge, I considered to leave only the decrypt functionality (do_task)
- damn, I should keep things simpler, sth like, for example,  decrypt orcale 
- make things more complicated can lead to unintended 😭

### ezCurve
Can you see that? It's not too complicated!

Attachment: *public.zip*

**Author:**
https://github.com/viensea1106/my-ctf-challenges/tree/main/wannagame-championship-2023/ezCurve


**© 2023,Pham Quoc Trung. All rights reserved.**
