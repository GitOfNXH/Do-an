from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np

# Hàm tải ảnh và chuyển đổi thành chuỗi byte
def load_image_as_bytes(filepath):
    img = Image.open(filepath)
    img_data = np.array(img)
    img_bytes = img_data.tobytes()  # Chuyển ảnh thành chuỗi byte
    return img, img_bytes

# Hàm chuyển bytes mã hóa thành ảnh mã hóa
def encrypted_bytes_to_image(encrypted_bytes, width, height):
    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)[:width * height * 3]
    encrypted_image = encrypted_array.reshape((height, width, 3))
    return Image.fromarray(encrypted_image)

# Hàm chuyển bytes thành ảnh
def decrypted_bytes_to_image(img, decrypted_bytes):
    img_data = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(img.size[1], img.size[0], -1)
    decrypted_image = Image.fromarray(img_data)
    return decrypted_image

# Hàm mã hóa và giải mã AES CBC
def aes_encrypt_image(image_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(image_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def aes_decrypt_image(image_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(image_bytes)
    decrypted_data = unpad(decrypted_padded, AES.block_size)
    return decrypted_data

def start():
    # Đường dẫn ảnh và thư mục lưu
    image_path = 'D:/Do_an/do_an/image/beach.png'  # Thay bằng ảnh gốc của bạn
    encrypted_image_path = 'D:/Do_an/do_an/image/AES_default/encrypted_image_default.png'
    decrypted_image_path = 'D:/Do_an/do_an/image/AES_default/decrypted_image_default.png'

    # Khóa AES 128-bit và IV
    key = b'nguyen xuan hieu'  
    iv = get_random_bytes(16)  

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
            encrypted_bytes = aes_encrypt_image(img_bytes, key, iv)
            print("Đã mã hóa dữ liệu")
        elif (condition == '3'):
            # 3. Giải mã ảnh
            decrypted_bytes = aes_decrypt_image(encrypted_bytes, key, iv)
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