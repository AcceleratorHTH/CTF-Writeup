def scramble(move, cube): 
    rounds = 1 
    if len(move) > 1: 
        if move[1] == '\'': 
            rounds = 3 
        elif move[1] == '2': 
            rounds = 2 
    U = [20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9] 
    U1 = [0, 1, 2, 5, 8, 7, 6, 3] 
    D = [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44] 
    D1 = [45, 46, 47, 50, 53, 52, 51, 48] 
    L = [0, 3, 6, 12, 24, 36, 45, 48, 51, 44, 32, 20] 
    L1 = [9, 10, 11, 23, 35, 34, 33, 21] 
    R = [53, 50, 47, 38, 26, 14, 8, 5, 2, 18, 30, 42] 
    R1 = [15, 16, 17, 29, 41, 40, 39, 27] 
    F = [6, 7, 8, 15, 27, 39, 47, 46, 45, 35, 23, 11] 
    F1 = [12, 13, 14, 26, 38, 37, 36, 24] 
    B = [2, 1, 0, 9, 21, 33, 51, 52, 53, 41, 29, 17] 
    B1 = [18, 19, 20, 32, 44, 43, 42, 30] 
    if move[0] == 'U': 
        old = U 
        old1 = U1 
    elif move[0] == 'D': 
        old = D 
        old1 = D1 
    elif move[0] == 'L': 
        old = L 
        old1 = L1 
    elif move[0] == 'R': 
        old = R 
        old1 = R1 
    elif move[0] == 'F': 
        old = F 
        old1 = F1 
    elif move[0] == 'B': 
        old = B 
        old1 = B1 
    else: 
        return 
    new = old[-rounds*3:] + old[:-rounds*3] 
    new1 = old1[-rounds*2:] + old1[:-rounds*2] 
    new = [cube[i] for i in new] 
    new1 = [cube[i] for i in new1] 
    cube = list(cube) 
    for i, c in zip(old, new): 
        cube[i] = c 
    for i, c in zip(old1, new1): 
        cube[i] = c 
    return bytes(cube)

def decrypt(ciphertext, move):
    IV = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv"

    ciphertext_blocks = [ciphertext[i*54:i*54+54] for i in range(len(ciphertext)//54)]
    
    out = b""
    
    for block in ciphertext_blocks:
        tmp = block
        for i in move.split(" "):
            block = scramble(i, block)
        pt = bytes([_a ^ _b for _a, _b in zip(block, IV)])
        out += pt
        IV = tmp

    return out

moves = "D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"
ciphertext = b';V".24$9\x0cw`\x02 \x16\x0b9j:2F\x128-x?\x05C\x1b3$\nShX*W\x01,\x025\x01\x0e\x17\x17\x01\x1c>X\x02C=\x00<\x1a0\x18>\x06\x00JE\x1e\x00\x16X\x0b \x0c\x1d\x08\r9\x0b0\x12q\x1fRS7\x0f3\x01tfa)\x07\x0ee3\n(<\x163j\x0b0.Z%%q8j$2'

print(decrypt(ciphertext, moves))