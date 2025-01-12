import os
from tqdm import tqdm

def random_key_generator(key_length):
    return bytes.hex(os.urandom(key_length // 8))

class AES:
    Nb = 4
    Nk = 4
    Nr = 10
    
    Sbox = (
        156, 72, 176, 149, 233, 250, 23, 73, 142, 62, 85, 117, 241, 223, 6, 193, 105, 88, 54, 70, 93, 197, 
        51, 128, 50, 125, 234, 141, 192, 79, 10, 227, 222, 171, 245, 129, 162, 57, 159, 118, 218, 5, 170, 
        74, 80, 92, 75, 44, 180, 136, 86, 8, 209, 126, 184, 103, 236, 224, 45, 181, 198, 115, 186, 253, 
        63, 9, 196, 137, 97, 53, 230, 15, 24, 81, 160, 213, 32, 163, 101, 59, 207, 114, 25, 96, 30, 94, 
        199, 64, 151, 247, 102, 82, 201, 152, 168, 203, 49, 116, 243, 7, 139, 189, 165, 66, 232, 254, 134, 
        112, 89, 191, 107, 18, 122, 16, 210, 255, 98, 55, 41, 14, 56, 13, 31, 4, 0, 33, 39, 158, 46, 77, 
        208, 238, 229, 188, 216, 121, 249, 204, 182, 183, 91, 248, 111, 252, 28, 150, 60, 108, 83, 179, 3,
        155, 61, 26, 215, 231, 130, 144, 166, 185, 37, 40, 237, 145, 172, 154, 12, 131, 212, 21, 169, 167, 
        206, 2, 228, 244, 242, 235, 214, 42, 52, 157, 211, 87, 175, 76, 221, 58, 220, 173, 119, 251, 187, 
        90, 35, 246, 104, 127, 148, 164, 120, 38, 17, 20, 195, 146, 124, 200, 240, 48, 99, 36, 123, 153, 
        225, 69, 67, 65, 143, 217, 140, 47, 34, 1, 133, 71, 43, 219, 178, 95, 202, 147, 110, 226, 29, 109, 
        84, 22, 138, 78, 132, 190, 106, 113, 135, 68, 100, 19, 239, 27, 11, 177, 205, 174, 194, 161
    )
    
    InvSbox = (
        124, 223, 173, 150, 123, 41, 14, 99, 51, 65, 30, 250, 166, 121, 119, 71, 113, 202, 111, 247, 203, 
        169, 237, 6, 72, 82, 153, 249, 144, 234, 84, 122, 76, 125, 222, 194, 211, 160, 201, 126, 161, 118,
        179, 226, 47, 58, 128, 221, 209, 96, 24, 22, 180, 69, 18, 117, 120, 37, 187, 79, 146, 152, 9, 64,
        87, 217, 103, 216, 245, 215, 19, 225, 1, 7, 43, 46, 185, 129, 239, 29, 44, 73, 91, 148, 236, 10, 
        50, 183, 17, 108, 193, 140, 45, 20, 85, 229, 83, 68, 116, 210, 246, 78, 90, 55, 196, 16, 242, 110,
        147, 235, 232, 142, 107, 243, 81, 61, 97, 11, 39, 190, 200, 135, 112, 212, 206, 25, 53, 197, 23, 
        35, 156, 167, 240, 224, 106, 244, 49, 67, 238, 100, 220, 27, 8, 218, 157, 163, 205, 231, 198, 3, 
        145, 88, 93, 213, 165, 151, 0, 181, 127, 38, 74, 255, 36, 77, 199, 102, 158, 171, 94, 170, 42, 33,
        164, 189, 253, 184, 2, 251, 228, 149, 48, 59, 138, 139, 54, 159, 62, 192, 133, 101, 241, 109, 28, 
        15, 254, 204, 66, 21, 60, 86, 207, 92, 230, 95, 137, 252, 172, 80, 130, 52, 114, 182, 168, 75, 178,
        154, 134, 219, 40, 227, 188, 186, 32, 13, 57, 214, 233, 31, 174, 132, 70, 155, 104, 4, 26, 177, 56,
        162, 131, 248, 208, 12, 176, 98, 175, 34, 195, 89, 141, 136, 5, 191, 143, 63, 105, 115
    )
    
    Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    def __init__(self, key, mode=128):
        if mode == 192:
            self.Nk = 6
            self.Nr = 12
            self.key = self.text2matrix(key, 24)
        elif mode == 256:
            self.Nk = 8
            self.Nr = 14
            self.key = self.text2matrix(key, 32)
        else:
            self.key = self.text2matrix(key)
        self.key_expansion(self.key)

    def text2matrix(self, text, len=16):
        state = []
        for i in range(len):
            # two hex characters == 1 byte
            byte = int(text[i*2:i*2+2], 16)
            if i % 4 == 0:
                # this means that the byte to append is the first of the column
                state.append([byte])
            else:
                # Append byte to the row i // 4 
                state[i // 4].append(byte) 
        return state

    def matrix2text(self, s, len=16):
        text = ""
        for i in range(len // 4):
            for j in range(4):
                text += format(s[i][j], '02x')
        return text

    def sub_bytes(self, s):
        for i in range(self.Nb):
            for j in range(4):
                s[i][j] = self.Sbox[s[i][j]]
    
    def inv_sub_bytes(self, s):
        for i in range(self.Nb):
            for j in range(4):
                s[i][j] = self.InvSbox[s[i][j]]

    def shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    def inv_shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

    def xtime(self, b):
        if b & 0x80:
            # check if b7 of the given polynomial is 1 or 0.
            b = b << 1
            b ^= 0x1B
        else:
            b = b << 1
        return b & 0xFF # get the first 8 bits.

    def mix_one_column(self, c):
        t = c[0] ^ c[1] ^ c[2] ^ c[3]
        u = c[0]
        c[0] ^= self.xtime(c[0] ^ c[1]) ^ t
        c[1] ^= self.xtime(c[1] ^ c[2]) ^ t
        c[2] ^= self.xtime(c[2] ^ c[3]) ^ t
        c[3] ^= self.xtime(c[3] ^ u) ^ t

    def mix_columns(self, s):
        for i in range(self.Nb):
            self.mix_one_column(s[i])

    def inv_mix_columns(self, s):
        for i in range(self.Nb):
            u = self.xtime(self.xtime(s[i][0] ^ s[i][2]))
            v = self.xtime(self.xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v
        self.mix_columns(s)

    def add_round_key(self, s, k):
        for i in range(self.Nb):
            for j in range(4):
                s[i][j] ^= k[i][j]

    def sub_word(self, w):
        for i in range(len(w)):
            w[i] = self.Sbox[w[i]]

    def rotate_word(self, w):
        w[0], w[1], w[2], w[3] = w[1], w[2], w[3], w[0]

    def key_expansion(self, key):
        self.round_keys = self.key
        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            self.round_keys.append([0, 0, 0, 0])
            temp = self.round_keys[i - 1][:]
            # word is multiple of Nk
            if i % self.Nk == 0:
                self.rotate_word(temp)
                self.sub_word(temp)
                temp[0] = temp[0] ^ self.Rcon[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                self.sub_word(temp)
            for j in range(4):
                self.round_keys[i][j] = self.round_keys[i - self.Nk][j] ^ temp[j]

    def cipher(self, text):
        self.state = self.text2matrix(text)
        self.add_round_key(self.state, self.round_keys[:4])
        for i in range(1, self.Nr):
            self.sub_bytes(self.state)
            self.shift_rows(self.state)
            self.mix_columns(self.state)
            self.add_round_key(self.state, self.round_keys[self.Nb * i : self.Nb * (i + 1)])
        self.sub_bytes(self.state)
        self.shift_rows(self.state)
        self.add_round_key(self.state, self.round_keys[len(self.round_keys) - 4:])
        return self.matrix2text(self.state)

    def decipher(self, text):
        self.encrypted_state = self.text2matrix(text)
        self.add_round_key(self.encrypted_state, self.round_keys[len(self.round_keys) - 4:])
        for i in range(self.Nr - 1, 0, -1):
            self.inv_shift_rows(self.encrypted_state)
            self.inv_sub_bytes(self.encrypted_state)
            self.add_round_key(self.encrypted_state, self.round_keys[self.Nb * i : self.Nb * (i + 1)])
            self.inv_mix_columns(self.encrypted_state)
        self.inv_shift_rows(self.encrypted_state)
        self.inv_sub_bytes(self.encrypted_state)
        self.add_round_key(self.encrypted_state, self.round_keys[:4])
        return self.matrix2text(self.encrypted_state)

def pad(block, block_length):
    bytes_to_pad = block_length - len(block) // 2
    for _ in range(bytes_to_pad):
        block += format(bytes_to_pad, '02x')
    return block

def unpad(block):
    bytes_to_unpad = int(block[-2:], 16)
    return block[:-bytes_to_unpad*2]

def xor_blocks(block_1, block_2):
    return format(int(block_1, 16) ^ int(block_2, 16), '032x')

def generate_random_iv(iv_length):
    return bytes.hex(os.urandom(iv_length))

def generate_random_ctr():
    return generate_random_iv(8) + "0000000000000000"

def increment_ctr(ctr):
    ctr_inc_int = int.from_bytes(bytes.fromhex(ctr), byteorder="big") + 1
    return bytes.hex(ctr_inc_int.to_bytes(length=16, byteorder="big"))

class ECB:
    def __init__(self, block_cipher_alg):
        self.block_cipher_alg = block_cipher_alg

    def cipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
        # check if last block need to be padded
        if len(hex_array[-1]) < 32:
            hex_array[-1] = pad(hex_array[-1], 16)
        cipher_array = []
        for i in tqdm(range(len(hex_array)), desc="ECB encryption"):
            cipher_array.append(self.block_cipher_alg.cipher(hex_array[i]))
        
        my_datas = bytearray()  
        for i in range(len(cipher_array)):
            my_datas.extend(bytes.fromhex(cipher_array[i]))
        return my_datas

    def decipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
            
        decrypted_array = []
        for i in tqdm(range(len(hex_array)), desc="ECB decryption"):
            decrypted_array.append(self.block_cipher_alg.decipher(hex_array[i]))
        # unpad last block
        decrypted_array[-1] = unpad(decrypted_array[-1])
        
        my_datas = bytearray()  
        for i in range(len(decrypted_array)):
            my_datas.extend(bytes.fromhex(decrypted_array[i]))
        return my_datas

class CBC:
    def __init__(self, block_cipher_alg, iv_length):
        self.block_cipher_alg = block_cipher_alg
        self.iv = generate_random_iv(iv_length)
        
    def cipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
        # Prefix the IV to the cipher text.
        cipher_array = [self.iv]
        iv = self.iv
        for i in tqdm(range(len(hex_array)), desc="CBC encryption"):
            block_to_cipher = xor_blocks(iv, hex_array[i])
            cipher_array.append(self.block_cipher_alg.cipher(block_to_cipher))
            # the ciphered block will be the "IV" for the next block
            iv = cipher_array[i + 1]
        # Khởi tạo biến my_datas là một bytearray
        my_datas = bytearray()  
        for i in range(len(cipher_array)):
            my_datas.extend(bytes.fromhex(cipher_array[i]))
        return my_datas

    def decipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
            
        iv = hex_array[0]
        decrypted_array = []
        for i in tqdm(range(1, len(hex_array)), desc="CBC decryption"):
            decrypted_array.append(self.block_cipher_alg.decipher(hex_array[i]))
            decrypted_array[i - 1] = xor_blocks(iv, decrypted_array[i - 1])
            # the ciphered block will be the "IV" for the next block
            iv = hex_array[i]
        
        my_datas = bytearray()  
        for i in range(len(decrypted_array)):
            my_datas.extend(bytes.fromhex(decrypted_array[i]))
        return my_datas

class CTR:
    def __init__(self, block_cipher_alg):
        self.block_cipher_alg = block_cipher_alg
        self.ctr = generate_random_ctr()
    
    def cipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
        # Prefix the ctr to the cipher text.
        cipher_array = [self.ctr]
        ctr = self.ctr
        for i in tqdm(range(len(hex_array)), desc="CTR encryption"):
            ctr_encrypted = self.block_cipher_alg.cipher(ctr)
            cipher_array.append(xor_blocks(ctr_encrypted, hex_array[i]))
            ctr = increment_ctr(ctr)
        # Khởi tạo biến my_datas là một bytearray
        my_datas = bytearray()  
        for i in range(len(cipher_array)):
            my_datas.extend(bytes.fromhex(cipher_array[i]))
        return my_datas
        
    def decipher(self, bytes_data):
        hex_array = []
        for offset in range(0, len(bytes_data), 16):
            hex_array.append(bytes_data[offset:offset + 16].hex())
        ctr = hex_array[0]
        decrypted_array = []
        for i in tqdm(range(1, len(hex_array)), desc="CTR decryption"):
            ctr_encrypted = self.block_cipher_alg.cipher(ctr)
            decrypted_array.append(xor_blocks(ctr_encrypted, hex_array[i]))
            ctr = increment_ctr(ctr)
        # decrypted_array[-1] = unpad(decrypted_array[-1])
        my_datas = bytearray()  # Khởi tạo biến my_datas là một bytearray
        for i in range(len(decrypted_array)):
            my_datas.extend(bytes.fromhex(decrypted_array[i]))
        return my_datas
