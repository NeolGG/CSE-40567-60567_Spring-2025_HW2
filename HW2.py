# Decryption
DEBUG = 1

import textwrap
from tables import IP_INVERSE,PC1,LEFT_SHIFTS,PC2, E, S_BOXES, P, IP

def permutate(table, input_val):
    output_val = ""
    
    for num in table:
        output_val += input_val[num - 1]
        
    return output_val

def de_permutate(table, output_val):
    table_size = len(table)
    input_val = ["0"] * table_size
    
    for i in range(table_size):
        input_val[table[i] - 1] = output_val[i]   
    
    return "".join(input_val)

def left_shift(bits, shift_count):
    """Perform left circular shift on a list of bits."""
    return bits[shift_count:] + bits[:shift_count]

def xor_binary_strings(bin1, bin2):
    """Perform XOR on two binary strings of equal length"""
    return "".join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bin1, bin2))

def binary_to_text(binary_string):
    byte_chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    
    text = ''.join(chr(int(byte, 2)) for byte in byte_chunks)
    
    return text

def get_keys(key) -> list:
    key_list = []
    print("-> Applying initial key permutation (PC1)")
    k_plus = permutate(PC1, key)
    
    print("-> Splitting permuted key into C0 and D0 halves")
    C0 = k_plus[0:28]
    D0 = k_plus[28:56]
    
    c = C0
    d = D0
    for i, shift in enumerate(LEFT_SHIFTS, start=1):
        print(f"-> Iteration {i}: Left shift applied with count {shift}")
        
        c, d = left_shift(c, shift), left_shift(d, shift)  
        
        print(f"\tApplying compression permutation (PC2)")
        key_list.append(permutate(PC2, c + d))  
    
    return key_list

def two_block_function(rn_1, kn):
    if DEBUG:print(f"Rn-1: {rn_1}")
    if DEBUG:print(f"kn: {kn}")
    if DEBUG:print()
    
    e_rn_1 = permutate(E,rn_1)
    if DEBUG:print(f"E(rn-1): {e_rn_1}")
    
    e_xor_kn = xor_binary_strings(e_rn_1, kn)
    if DEBUG:print(f"e_xor_kn: {e_xor_kn}")

    byte_groups = textwrap.wrap(e_xor_kn, 6)
    
    for i in range(len(byte_groups)):
        if DEBUG:print(f"block {i+1}: {byte_groups[i]}")
    
    new_output = ""
    
    for i in range(8):
        SI = S_BOXES[i]
        BI = byte_groups[i]
        
        row = int(BI[0] + BI[-1],2)
        column = int(BI[1:5],2)
        four_bit = format(SI[row][column], '04b')
        
        if DEBUG:print(f"S-Box-{i+1:2} = Row: {row:2}, Column: {column:2} --> {four_bit:>4}")
        
        new_output += four_bit

    new_output = permutate(P, new_output)
    if DEBUG:print(f"f ouput: {new_output}")
    
    return new_output

def decrypt_DES(cipher_text, key):
    # get key list--------------------------------------------------
    print("generate 16 sub-keys")
    key_list = get_keys(key)

    print("\nKey list")
    for i in range(len(key_list)):
        print(f"K{i+1} = {key_list[i]}")

    IP_R16L16 = cipher_text

    # de_permutate the IP_R16L16
    print()
    print("de-permutate inverse IP cipher text")
    print(f"Cipher text (post IP_R16L16): {cipher_text}")
    R16L16 = de_permutate(IP_INVERSE, IP_R16L16)
    print(f"after inverse permutation (R16L16): {R16L16}")

    print("split R16L16 into L16 (right half) and R16 (left half)")
    L16 = R16L16[32:64]
    R16 = R16L16[0:32]

    K16 = key_list[-1] # last key of the list

    print()
    print(f"L16: {L16}")
    print(f"R16: {R16}")
    print(f"K16: {K16}")
    print()

    print("start decrypting rounds (Feistel rounds)")
    L15 = xor_binary_strings(R16,two_block_function(L16,K16))
    print(f"Round 16, L15: {L15}\n")

    # Initial parameters, starting from L16, R16
    LN = L16  
    RN = R16  
    KN = key_list.pop()  # K16

    for i in range(16):
        generation = 16 - i
        print(f"--- Decryption Round {generation} ---")
        print(f"K{generation} = {KN}")
        print(f"L{generation} = R{generation-1} = {LN}")
        print(f"R{generation} = L{generation-1} ^ f(R{generation-1}, K{generation})")
        print(f"L{generation-1} = R{generation} ^ f(R{generation-1}, K{generation})")

        # solve for Ln-1
        LN_1 = xor_binary_strings(RN, two_block_function(LN, KN))

        print(f"L{generation-1} = {LN_1}")
        print()
        if key_list:
            KN = key_list.pop()
        else:
            break
        
        RN_1 = LN  # R(n-1) = L(n)
        LN, RN = LN_1, RN_1  # Swap L and R for the next round

    print(f"Original K1, L1, R1")
    generation = 1
    print(f"K{generation} = {KN}")
    print(f"L{generation} = R{generation-1} = {LN}")
    print(f"R{generation} = L{generation-1} ^ f(R{generation-1}, K{generation})")
    print(f"L{generation-1} = {LN_1}")

    # de_permutate
    L0 = LN_1
    R0 = LN
    print()
    print(f"L0: {L0}")
    print(f"R0: {R0}")

    M_IP = L0 + R0
    print(f"M_IP: {M_IP}")
    
    print("\nde-permutate M ")
    M = de_permutate(IP, M_IP)
    message = hex(int(M, 2))[2:]
    plaintext = binary_to_text(M)

    # decrypted message)
    print(f"M : {M}")
    print(f"Message_Hex: {message}")
    print(f"Message: {plaintext}")

if __name__ == "__main__":
    CIPHER_TEXT = "1100101011101101101000100110010101011111101101110011100001110011"
    KEY = "0100110001001111010101100100010101000011010100110100111001000100"
    
    decrypt_DES(CIPHER_TEXT,KEY)