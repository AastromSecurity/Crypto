#!/usr/bin/env python3

# @author:                      AastromSecurity
# @lastUpdate:                  2019-05-03
# @role:                        RSA implementation / Fast Modular Exponentiation
# @comments:                    ESGI - Advanced Cryptography
# @version:                     v1.0

import argparse, os, random, sys

# Mandatory for recursive generation of large random numbers
sys.setrecursionlimit(1000000)

# Public ciphering exponent
public_exponent = 65537

# User home path
home_path = os.path.expanduser('~')

# RSA paths to store public and private keys
rsa_path = home_path + "/.rsa"
rsa_pubpath = rsa_path + "/public"; rsa_privpath = rsa_path + "/private"
rsa_pubfile = rsa_pubpath + "/public_key"; rsa_privfile = rsa_privpath + "/private_key"

# Generates a fixed-size prime number
def gen_prime_by_length(n: int):
    return next_probable_prime(gen_random_by_length(n))

# Generates a fixed-size odd random number
def gen_random_by_length(n: int):
    start = 10 ** (n - 1); end = (10 ** n) - 1
    rand = random.randint(start, end)
    if rand % 2 == 0: rand += 1
    return rand

# Generates a tuple composed of RSA public and private keys
def gen_rsa_keys(nb_bits: int):
    sys.stdout.write("(\033[32;1m~\033[0m) Generating two " + (str)(nb_bits // 2) + " digits-long random prime numbers, please wait... "); sys.stdout.flush()
    a = gen_prime_by_length(nb_bits // 2); b = gen_prime_by_length(nb_bits // 2); print("\033[32;1mOK\033[0m")
    sys.stdout.write("(\033[32;1m~\033[0m) Generating public and private keys based on prime numbers... "); sys.stdout.flush()
    n = a * b; phi = (a - 1) * (b - 1); e = public_exponent; d = inverse_modulo(e, phi); print("\033[32;1mOK\033[0m")
    return (n, e, d)

# Creates RSA folders in the user's home directory
def gen_rsa_folders():
    if not os.path.exists(rsa_path): os.mkdir(rsa_path)
    if not os.path.exists(rsa_pubpath): os.mkdir(rsa_pubpath)
    if not os.path.exists(rsa_privpath): os.mkdir(rsa_privpath)

# Generates parser
def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cipher", help="process RSA ciphering", action="store_true")
    parser.add_argument("-d", "--decipher", help="process RSA deciphering", action="store_true")
    parser.add_argument("-g", "--generate", help="process nb_bits keys generation", action="store", type=int, metavar="NB_BITS")
    parser.add_argument("-m", "--message", help="message (int) to process over RSA cipher or decipher", action="store", type=int)    
    return parser

# Returns the inverse modulo of integers passed as parameters based on Euclid's extended algorithm
def inverse_modulo(a: int, b: int):
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, b
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % b

# Determines if the integer passed in parameter is a prime number with a strong probability
def is_probable_prime(n: int):
    if n == 2 or n == 3: return True
    if n <= 1 or n % 2 == 0: return False
    r = n - 1; s = 0
    while r & 1 == 0: s += 1; r //= 2
    k = random.randint(2, 40)
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1: return False
                j += 1
            if x != n - 1: return False
    return True

# Main function
def main():
    args = get_parser().parse_args(); gen_rsa_folders()
    if not os.path.isfile(rsa_pubfile) or not os.path.isfile(rsa_privfile):
        if args.generate: write_rsa_keys(gen_rsa_keys(args.generate)); sys.exit(0)
        else: print("[\033[31;1m!\033[0;m]  You need to generate RSA keys for the first time !\n     Please restart the program with the following syntax: './rsa_cipher.py --generate [nb_bits]'.\n     For more information on using this program, issue the command './rsa_cipher.py --help'."); sys.exit(1)
    if args.generate: nb_bits = args.generate; write_rsa_keys(gen_rsa_keys(nb_bits)); sys.exit(0)
    if args.message: message = args.message
    rsa_pubkey, rsa_privkey = read_rsa_keys()
    if args.cipher: print("\033[1mENCRYPTED : \033[32;1m" + str(rsa_cipher(message, public_exponent, rsa_pubkey)) + "\033[0m")
    if args.decipher: print("\033[1mDECRYPTED : \033[32;1m" + str(rsa_decipher(message, rsa_privkey, rsa_pubkey)) + "\033[0m")

# Returns the most likely prime number that follows the odd integer passed as parameter
def next_probable_prime(a: int):
    if is_probable_prime(a) is False: return next_probable_prime(a + 2)
    else: return a

# Reads files containing public and private RSA keys and returns a tuple
def read_rsa_keys():
    with open(rsa_pubfile, 'r') as public_keyfile, open(rsa_privfile, 'r') as private_keyfile:
        return (int(public_keyfile.read(), base=16), int(private_keyfile.read(), base=16))

# RSA encryption method based on fast modular exponentation
def rsa_cipher(decrypted: int, e: int, n: int):
    return pow(decrypted, e, n)

# RSA decryption method based on fast modular exponentation
def rsa_decipher(encrypted: int, d: int, n: int):
    return pow(encrypted, d, n)

# Writes RSA public and private keys in hexadecimal form
def write_rsa_keys(keys: tuple):
    public_key = keys[0]; private_key = keys[2]
    sys.stdout.write("(\033[32;1m~\033[0m) Storing public and private keys into filesystem... ")
    with open(rsa_pubfile, 'w') as public_keyfile, open(rsa_privfile, 'w') as private_keyfile:
        public_keyfile.write(hex(public_key)); private_keyfile.write(hex(private_key)); print("\033[32;1mOK\033[0m")

# Returns a tuple composed of the GCD and Bezout coefficients for integers passed as parameters
def xgcd(a: int, b: int):
    if a == 0: return (b, 0, 1)
    else: g, x, y = xgcd(b % a, a); return (g, x - (b // a) * y, y)

if __name__ == "__main__":
    main()
