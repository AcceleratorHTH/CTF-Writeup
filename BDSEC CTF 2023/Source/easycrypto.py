import argparse

cbase = [chr(x) + chr(y) for x in range(32, 128) for y in range(32, 128)]
alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

def base36encode(number):

    if not isinstance(number, int):
        raise TypeError("Input must be an integer")
    if number < 0:
        raise ValueError("Number must be positive")
    encoded_string = ""
    while number:
        number, i = divmod(number, 36)
        encoded_string = alphabet[i] + encoded_string
    return encoded_string or alphabet[0]

def twin_hex_encrypt(input_str):

    encrypted_str = ""
    for i in range(0, len(input_str), 2):
        pair = input_str[i : i + 2]
        if len(pair) < 2:
            pair += " "
        encrypted_str += base36encode(cbase.index(pair)).ljust(3, " ")
    return encrypted_str

def twin_hex_decrypt(input_str):

    decrypted_str = ""
    try:
        triples = [input_str[i : i + 3] for i in range(0, len(input_str), 3)]
        decrypted_str += "".join(cbase[int(x, 36)] for x in triples if x.strip())
    except ValueError as e:
        print(f"Error: Invalid input - {str(e)}")
    except Exception as e:
        print(f"Error: {str(e)}")
    return decrypted_str

stre = "1e25v768h1e66dw61v1hv1kl6aa1ei1pw1pv1ju1kj5ps1bb6lw624"
print(twin_hex_decrypt(twin_hex_decrypt(stre)))
