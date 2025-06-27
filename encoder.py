# encoder.py

from PIL import Image
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def to_bin(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, int):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")

def encrypt(message, password):
    key = SHA256.new(password.encode('utf-8')).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = iv + cipher.encrypt(message.encode('utf-8'))
    return encrypted

def encode(image_path, message, password, output_path):
    img = Image.open(image_path).convert("RGB")
    encoded = img.copy()
    width, height = img.size
    pixels = encoded.load()

    encrypted_message = encrypt(message, password)
    encrypted_message += b"#####"
    binary_message = ''.join([format(byte, "08b") for byte in encrypted_message])
    message_len = len(binary_message)
    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index < message_len:
                r, g, b = img.getpixel((x, y))
                r_bin = to_bin(r)
                g_bin = to_bin(g)
                b_bin = to_bin(b)

                if data_index < message_len:
                    r_bin = r_bin[:-1] + binary_message[data_index]
                    data_index += 1
                if data_index < message_len:
                    g_bin = g_bin[:-1] + binary_message[data_index]
                    data_index += 1
                if data_index < message_len:
                    b_bin = b_bin[:-1] + binary_message[data_index]
                    data_index += 1

                pixels[x, y] = (int(r_bin, 2), int(g_bin, 2), int(b_bin, 2))
            else:
                break

    encoded.save(output_path)
    print("[+] Encoding complete. Saved as", output_path)

if __name__ == "__main__":
    input_image = "input.png"
    output_image = "output.png"
    secret_message = "This is a top secret hidden message."
    password = input("Enter passsword")

    encode(input_image, secret_message, password, output_image)
