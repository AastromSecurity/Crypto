#!/usr/bin/env python3

# @author:                      Antoine HENRY
# @lastUpdate:                  2019-04-14
# @role:                        Affine ciphering and deciphering
# @comments:                    ESGI - Advanced Cryptography - TD1
# @version:                     v1.0 - Uppercase charset

import argparse, sys

chset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def affine_ciphering(decrypted: str, a: int, b: int):
    encrypted = ""
    for d in decrypted:
        e = chset[((a * chset.index(d) + b) % 26)] if d != " " else d
        encrypted += e
    return encrypted

def affine_deciphering(encrypted: str, a: int, b: int):
    decrypted = ""
    for e in encrypted:
        d = chset[(inverse_modulo26(a) * (chset.index(e) - b)) % 26] if e != " " else e
        decrypted += d
    return decrypted

def inverse_modulo26(a: int):
    x = 0
    while(a * x % 26 != 1):
        x += 1
    return x

def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", help="specify action to process over string (cipher or decipher)", action="store", type=str, metavar="action")
    parser.add_argument("string", help="string to process", action="store", type=str, metavar="string")
    parser.add_argument("a_key", help="A key", action="store", type=int, metavar="A")
    parser.add_argument("b_key", help="B key", action="store", type=int, metavar="B")
    return parser

def main():
    args = get_parser().parse_args()
    action = args.action; string = args.string.upper(); a_key = args.a_key; b_key = args.b_key
    if a_key <= 0 or b_key <= 0:
        print("[\033[31;1mx\033[0;m]  Error : a_key and b_key must both be positive integers !\n"); sys.exit(1)
    if action == "cipher":
        print(affine_ciphering(string, a_key, b_key)); sys.exit(0)
    elif action == "decipher":
        print(affine_deciphering(string, a_key, b_key)); sys.exit(0)
    else:
        print("[\033[31;1mx\033[0;m]  Error : unknown action " + action + " ! Please retry with 'cipher' or 'decipher'.\n"); sys.exit(1)

if __name__ == "__main__":
    main()











