# decoder.py

from PIL import Image
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def to_bin(data):
    if isinstance(data, int):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")

def decrypt(encrypted, password):
    key = SHA256.new(password.encode('utf-8')).digest()
    iv = encrypted[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(encrypted[AES.block_size:])
    return decrypted.decode('utf-8')

def decode(image_path, password):
    img = Image.open(image_path).convert("RGB")
    binary_data = ""
    imgdata = img.getdata()

    for pixel in imgdata:
        for color in pixel[:3]:
            binary_data += to_bin(color)[-1]

    # Split by 8 bits
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_bytes = bytearray()
    for byte in all_bytes:
        decoded_bytes.append(int(byte, 2))
        if decoded_bytes[-5:] == b"#####":
            break

    encrypted_message = decoded_bytes[:-5]

    try:
        decrypted_message = decrypt(encrypted_message, password)
        return decrypted_message
    except:
        return "[!] Incorrect password or corrupted data."

if __name__ == "__main__":
    encoded_image = "output.png"
    password = input("Enter password to extract message: ")
    message = decode(encoded_image, password)
    print("[+] Decoded message:", message)
