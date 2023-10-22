import os
import base64
import traceback
from flask import Flask, request
from html import escape

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


app = Flask(__name__)

page = '''
<html>
<head><title>Welcome</title></head>
<body>
  <p><h2>Welcome, %s!</h2></p>
  <p><h3>You have %s tickets left</h3></p>
  <p>%s</p>
</body>
</html>
'''

key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


def get_ticket(username, email, amount):
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    message = padder.update("%s&%s&%d" % (username, email, amount)) + padder.finalize()
    ct = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(ct)

def padding_oracle(ciphertext):
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        message = decryptor.update(ciphertext) + decryptor.finalize()
        _ = (unpadder.update(message) + unpadder.finalize()).split('&')
        return True
    except Exception:
        return False

def padding_oracle_attack(ciphertext):
    block_size = 16
    plaintext = bytearray()

    for block_index in range(len(ciphertext) // block_size - 1, -1, -1):
        previous_block = ciphertext[block_index * block_size : (block_index + 1) * block_size]
        current_block = ciphertext[(block_index + 1) * block_size : (block_index + 2) * block_size]
        intermediate = bytearray(block_size)

        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            padding_oracle_ciphertext = bytearray(previous_block)
            for i in range(byte_index + 1, block_size):
                padding_oracle_ciphertext[i] ^= intermediate[i] ^ padding_value
            found_byte = False
            for guess in range(256):
                padding_oracle_ciphertext[byte_index] = guess
                if padding_oracle(padding_oracle_ciphertext):
                    intermediate[byte_index] = guess ^ padding_value
                    found_byte = True
                    break
            if not found_byte:
                raise ValueError("Padding oracle attack failed.")
        plaintext = intermediate + plaintext

    return bytes(plaintext)

@app.route('/')
def default():
    try:
        ticket = request.cookies.get('ticket')
        if ticket:
            decrypted_message = padding_oracle_attack(base64.b64decode(ticket))
            username, email, amount = decrypted_message.decode().split('&')
            return page % (escape(username), escape(amount),
                           'I cannot lead you towards glorious times' if amount == '1' else
                           'Baaam! You are the Woodpecker No.1!')
        else:
            return '<html><body><p><a href=/ticket>Get a free ticket, but only one!</a></p></body><html>\n'
    except Exception as e:
        print(traceback.format_exc())
        raise ValueError(str(e))

@app.route('/ticket', methods=['POST'])
def ticket():
    username = request.form.get('username')
    email = request.form.get('email')
    if username and email:
        ticket = get_ticket(username, email, 1)
        response = app.make_response('<html><body><p>So you said you are ready to ascend a mountain of heavy light?</p></body></html>\n')
        response.set_cookie('ticket', ticket.decode())
        return response
    raise ValueError('Post me your username and email')

if __name__ == "__main__":
    app.run(host='localhost', port=8080)
