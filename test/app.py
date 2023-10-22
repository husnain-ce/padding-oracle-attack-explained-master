import os
import base64
import traceback
from flask import Flask, request, render_template_string, make_response
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

ticket_form = '''
<html>
<head><title>Get a Ticket</title></head>
<body>
  <form method="post" action="/ticket">
    <label for="username">Username:</label>
    <input type="text" name="username" id="username" required><br><br>
    
    <label for="email">Email:</label>
    <input type="email" name="email" id="email" required><br><br>

    <input type="submit" value="Get Ticket">
  </form>
</body>
</html>
'''

key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())


def get_ticket(username, email, amount):
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    message = ("%s&%s&%d" % (username, email, amount)).encode('utf-8')
    message = padder.update(message) + padder.finalize()
    ct = encryptor.update(message) + encryptor.finalize()
    print(ct)
    return base64.b64encode(ct)


def padding_oracle(ciphertext):
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        message = decryptor.update(ciphertext) + decryptor.finalize()
        _ = (unpadder.update(message) + unpadder.finalize()).split(b'&')
        return True
    except Exception:
        return False

def padding_oracle_attack(ciphertext):
    BLOCK_SIZE = 16
    plaintext = bytearray()

    for block_index in range(len(ciphertext) // BLOCK_SIZE - 1, -1, -1):
        previous_block = ciphertext[block_index * BLOCK_SIZE: (block_index + 1) * BLOCK_SIZE]
        current_block = ciphertext[(block_index + 1) * BLOCK_SIZE: (block_index + 2) * BLOCK_SIZE]
        intermediate = bytearray(BLOCK_SIZE)

        for byte_index in range(BLOCK_SIZE - 1, -1, -1):
            padding_value = 1 if byte_index == BLOCK_SIZE - 1 else BLOCK_SIZE - byte_index
            padding_oracle_ciphertext = bytearray(previous_block)

            for i in range(byte_index + 1, BLOCK_SIZE):
                padding_oracle_ciphertext[i] ^= intermediate[i] ^ padding_value

            for guess in range(256):
                padding_oracle_ciphertext[byte_index] = guess
                if padding_oracle(padding_oracle_ciphertext + current_block):
                    intermediate[byte_index] = guess ^ padding_value
                    break
            else:
                # Backtrack and modify the last byte of the previous block
                prev_byte_index = byte_index + 1
                while prev_byte_index < BLOCK_SIZE:
                    padding_oracle_ciphertext[prev_byte_index] ^= intermediate[prev_byte_index] ^ (BLOCK_SIZE - byte_index)
                    prev_byte_index += 1
                continue

            # Check if the decrypted block is valid before appending it
            if all(0 <= byte < BLOCK_SIZE for byte in intermediate):
                plaintext = intermediate + plaintext
            else:
                print(f"Block index {block_index}: Padding oracle attack failed.")
                raise ValueError("Padding oracle attack failed.")

    print(f"Decrypted message (hex): {plaintext.hex()}")
    return bytes(plaintext)



@app.route('/clear_cookie')
def clear_cookie():
    response = make_response("Cookie cleared!")
    response.delete_cookie('ticket')
    return response


# New route for displaying the main page
@app.route('/')
def default():
    try:
        ticket = request.cookies.get('ticket')
        if ticket:
            decrypted_message = padding_oracle_attack(base64.b64decode(ticket))
            print(f"Decrypted message (hex): {decrypted_message.hex()}")
            username, amount = decrypted_message.split(b'&')
            print(f"Username (hex): {username.hex()}")
            print(f"Amount (hex): {amount.hex()}")
            return page % (escape(username.decode()), escape(amount.decode()),
                           'I cannot lead you towards glorious times' if amount == b'1' else
                           'Baaam! You are the Woodpecker No.1!')
        else:
            return render_template_string(ticket_form)  # Render the form template
    except Exception as e:
        print(traceback.format_exc())
        return "An error occurred. Please try again later."


@app.route('/ticket', methods=['POST'])
def ticket():
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        if username and email:
            ticket = get_ticket(username, email, 1)
            response = app.make_response('<html><body><p>So you said you are ready to ascend a mountain of heavy light?</p></body></html>\n')
            response.set_cookie('ticket', ticket.decode())
            return response
        else:
            raise ValueError('Post me your username and email')
    except Exception as e:
        print(traceback.format_exc())
        return "An error occurred. Please try again later."


if __name__ == "__main__":
    app.run(host='localhost', port=8080)
