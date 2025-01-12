import numpy as np

def create_sbox(x0, r):
    arrS = []
    i = 0
    arrX = [x0]
    while len(arrS) < 256:
        before = arrX[i]
        value = r * before * (1 - before)
        arrX.append(value)
        h = before.hex()[8:10]
        if h in arrS:
            i += 1
        else:
            arrS.append(h)  # Lưu giá trị hex vào mảng
            i += 1
    sbox = np.array(arrS).reshape(16, 16)
    sbox_tuple = tuple(int(value, 16) for row in sbox for value in row)
    sbox_format = '\n'.join([' '.join(row) for row in sbox])
    return sbox, sbox_tuple, sbox_format

def create_invsbox(sbox):
    inv_sbox = np.zeros((16, 16), dtype='U2')
    for i in range(16):
        for j in range(16):
            a, b = sbox[i, j]
            a = int(a, 16)  
            b = int(b, 16)  
            i_hex = hex(i)[2:]  
            j_hex = hex(j)[2:] 
            inv_sbox[a, b] = '{}{}'.format(i_hex, j_hex)
    inv_sbox_tuple = tuple(int(value, 16) for row in inv_sbox for value in row)
    inv_sbox_format = '\n'.join([' '.join(row) for row in inv_sbox])
    return inv_sbox_tuple, inv_sbox_format

def start():
    # Tạo s_box và reversed_s_box
    sbox, sbox_tuple, sbox_format = create_sbox(0.00131, 3.64103)
    inv_sbox_tuple, inv_sbox_format = create_invsbox(sbox)

    print("\n================================\n")
    print("Ma trận Sbox: ")
    print(sbox_format)
    print("\n================================\n")
    print("Ma trận Sbox đảo ngược: ")
    print(inv_sbox_format)

    # Ghi dữ liệu vào file
    with open('sbox_tuple.txt', 'w') as file:
        file.write("sbox_tuple = " + str(sbox_tuple) + "\n")
        file.write("inv_sbox_tuple = " + str(inv_sbox_tuple) + "\n")
    print("sbox_tuple và inv_sbox_tuple đã được lưu vào file sbox_tuple.txt")

start()

