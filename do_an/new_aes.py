from PIL import Image
import numpy as np
import aes

# Hàm để tải ảnh và chuyển ảnh thành chuỗi byte
def load_image_as_bytes(filepath):
    img = Image.open(filepath)
    img_data = np.array(img)
    img_bytes = img_data.tobytes()  # Chuyển ảnh thành chuỗi byte
    print(len(img_bytes))
    return img, img_bytes

# Hàm chuyển bytes mã hóa thành ảnh mã hóa
def encrypted_bytes_to_image(encrypted_bytes, width, height):
    print(len(encrypted_bytes))
    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)[:width * height * 3]
    encrypted_image = encrypted_array.reshape((height, width, 3))
    return Image.fromarray(encrypted_image)

# Hàm chuyển bytes thành ảnh
def decrypted_bytes_to_image(img, decrypted_bytes):
    print(len(decrypted_bytes))
    img_data = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(img.size[1], img.size[0], -1)
    decrypted_image = Image.fromarray(img_data)
    return decrypted_image

def encrypt(img_bytes, block_cipher_mode, key_length):
    key = aes.random_key_generator(int(key_length))
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
    encrypted_data = bcm.cipher(img_bytes)
    write_key(key)
    print("Cipher Key:", key)
    return encrypted_data

def decrypt(encrypted_data, block_cipher_mode):
    key = read_key()
    key_length = len(key) * 4
    
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
    # Đường dẫn đến ảnh trên máy tính
    image_path = 'D:/Do_an/do_an/image/beach.png'
    encrypted_image_path = 'D:/Do_an/do_an/image/s_box_other/encrypted_image.png'
    decrypted_image_path = 'D:/Do_an/do_an/image/s_box_other/decrypted_image.png'
    
    while True:
        print("================================================================\n")
        print("1. Tải ảnh, chuyển sang chuỗi byte")
        print("2. Mã hóa chuỗi byte hình ảnh")
        print("3. Giải mã chuỗi byte hình ảnh")
        print("4. Dựng hình ảnh từ chuỗi bytes đã được mã hóa và lưu hình ảnh")
        print("5. Dựng hình ảnh từ chuỗi bytes đã được giải mã và lưu hình ảnh")
        print("0. Thoát chương trình")
        condition = input("Nhập lựa chọn: ")
        
        if (condition == '1'):
            # 1. Tải ảnh và chuyển sang chuỗi byte
            original_img, img_bytes = load_image_as_bytes(image_path)
            print("Chuyển đổi hình ảnh thành bytes thành công!")
        elif (condition == '2'):
            # 2. Mã hóa ảnh
            encrypted_bytes = encrypt(img_bytes, 'CBC', 128)
            print("Đã mã hóa dữ liệu")
        elif (condition == '3'):
            # 3. Giải mã ảnh
            decrypted_bytes = decrypt(encrypted_bytes, 'CBC')
            print("Đã giải mã dữ liệu")
        elif (condition == '4'):
            # 4. Lưu ảnh mã hóa dưới dạng ảnh
            encrypted_image = encrypted_bytes_to_image(encrypted_bytes, original_img.size[0], original_img.size[1])
            encrypted_image.save(encrypted_image_path)
            print("Lưu hình ảnh mã hóa thành công")
        elif (condition == '5'):
             # 5. Lưu ảnh đã giải mã dưới dạng ảnh
            decrypted_image = decrypted_bytes_to_image(original_img, decrypted_bytes)
            decrypted_image.save(decrypted_image_path)
            print("Lưu hình ảnh giải mã thành công")
        elif (condition == '0'):
            break
        else:
            print("Giá trị nhập vào không hợp lệ, vui lòng nhập lại!")
        
start()