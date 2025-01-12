import aes

def encrypt(data, block_cipher_mode, key_length):
    key = aes.random_key_generator(key_length)
    if key_length == 128:
        AES = aes.AES(key, 128)
    elif key_length == 192:
        AES = aes.AES(key, 192)
    elif key_length == 256:
        AES = aes.AES(key, 256)
    if block_cipher_mode == "ECB":
        bcm = aes.ECB(AES)
    elif block_cipher_mode == "CBC":
        bcm = aes.CBC(AES, 16)
    elif block_cipher_mode == "CTR":
        bcm = aes.CTR(AES)
    encrypted_data = bcm.cipher(data)
    write_key(key)
    print("Cipher Key:", key)
    return encrypted_data

def decrypt(encrypted_data, block_cipher_mode):
    key = read_key()
    if key == 1:
        print("File key.txt doesn't exists! Can't decrypt without key")
        exit(1)
    key_length = len(key) * 4
    if key_length == 128:
        AES = aes.AES(key, 128)
    elif key_length == 192:
        AES = aes.AES(key, 192)
    elif key_length == 256:
        AES = aes.AES(key, 256)
    else:
        print("Key length not valid!")
        exit(1)
    if block_cipher_mode == "ECB":
        bcm = aes.ECB(AES)
    elif block_cipher_mode == "CBC":
        bcm = aes.CBC(AES, 16)
    elif block_cipher_mode == "CTR":
        bcm = aes.CTR(AES)
    decrypted_data = bcm.decipher(encrypted_data)
    return decrypted_data

def read_key():
    with open("key.txt", "r") as f:
        key = f.read()
    return key

def write_key(key):
    with open("key.txt", "w") as f:
        f.write(key)
        
def start():
    my_datas = 'Nguyen Xuan Hieu - AT170119 - Do an tot nghiep'
    encrypt_datas = encrypt(my_datas.encode('utf-8'), 'CBC', 192)
    decrypt_datas = decrypt(encrypt_datas, 'CBC')
    print('Dữ liệu khi được mã hóa: ', encrypt_datas)
    print('Dữ liệu sau khi được giải mã: ', decrypt_datas.decode('utf-8'))
    
start()