#!/usr/bin/env python3

# @author:                      Antoine HENRY
# @lastUpdate:                  2019-05-03
# @role:                        Feistel ciphering and deciphering
# @comments:                    ESGI - Advanced Cryptography
# @version:                     v1.0

import argparse, sys

def feistel_ciphering(decrypted: str):
    encrypted = ""
    g0 = decrypted[0:2]; d0 = decrypted[2:4]; g1 = d0
    d1 = str(bin(int(g0, 2) ^ int(function1(d0), 2)).replace('0b', ''))
    if len(d1) == 1: d1 += "0"
    g2 = d1; d2 = str(bin(int(g1, 2) ^ int(function2(d1), 2)).replace('0b', ''))
    if len(d2) == 1: d2 += "0"
    encrypted = g2 + d2
    return encrypted

def feistel_deciphering(encrypted: str):
    decrypted = ""
    d2 = encrypted[2:4]; g2 = encrypted[0:2]; d1 = g2
    g1 = str(bin(int(d2, 2) ^ int(function2(g2), 2)).replace('0b', ''))
    if len(g1) == 1: g1 += "0"
    d0 = g1; g0 = str(bin(int(d1, 2) ^ int(function1(g1), 2)).replace('0b', ''))
    if len(g0) == 1: g0 += "0"
    decrypted = d0 + g0
    return decrypted

def function1(bits: str):
    if bits == "00": return "01"
    if bits == "01": return "11"
    if bits == "10": return "10"
    if bits == "11": return "01"

def function2(bits: str):
    if bits == "00": return "11"
    if bits == "01": return "00"
    if bits == "10": return "00"
    if bits == "11": return "01"

def get_parser():
    parser= argparse.ArgumentParser()
    parser.add_argument("action", help="specify action to process over string (cipher or decipher)", action="store", type=str, metavar="action")
    parser.add_argument("string", help="string to process", action="store", type=str, metavar="string")
    return parser

def main():
    args = get_parser().parse_args()
    action = args.action; string = args.string
    if action == "cipher": print(feistel_ciphering(string))
    elif action == "decipher": print(feistel_deciphering(string))
    else: print("[\033[31;1mx\033[0;m]  Error : unknown action " + action + " ! Please retry with 'cipher' or 'decipher'.\n"); sys.exit(1)

if __name__ == "__main__":
    main()
