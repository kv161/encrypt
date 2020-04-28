
from flask import Flask, request, redirect, url_for, render_template, session, send_from_directory, send_file
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet




def generatenewkey(key):
	password_provided = str(key) # This is input in the form of a string
	password = password_provided.encode() # Convert to type bytes
	salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
	kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=salt,
	    iterations=100000,
	    backend=default_backend()
	)
	key = base64.urlsafe_b64encode(kdf.derive(password))
	return key
#app.secret_key = 'SECRET KEY'
app = Flask(__name__)
def encrypt(key,message):
	newkey=generatenewkey(key)
	print ("new key is ",newkey)
	print (message)
	message = message.encode()
	f = Fernet(newkey)
	encrypted = f.encrypt(message)
	encrypted=encrypted.decode()
	return encrypted

def decrypt(key,message):
	newkey=generatenewkey(key)
	print ("new key is ",newkey)
	print (message)
	message = message.encode()
	f = Fernet(newkey)
	decrypted = f.decrypt(message)
	decrypted=decrypted.decode()
	return decrypted


@app.route('/encrypttext', methods=['GET', 'POST'])
def encrypttext():
	key = request.form['privatekey']
	message = request.form['message']
	encryptedtext=encrypt(key,message)
	#encryptedtext=decrypt(key,message)
	return render_template('result.html',value=encryptedtext)

@app.route('/decrypttext', methods=['GET', 'POST'])
def decrypttext():
	key = request.form['privatekey']
	message = request.form['message']
	#encryptedtext=encrypt(key,message)


	try:
		encryptedtext=decrypt(key,message)
	except:
		encryptedtext='Sorry! wrong combination of key and encrypted text,please try again'
	return render_template('result.html',value=encryptedtext)


@app.route('/enterkeysforde')
def enterkeysforde():
	return render_template('enterkeysforde.html')
@app.route('/enterkeysforen')
def enterkeysforen():
	return render_template('enterkeysforen.html')

@app.route('/')
def call_page_upload():
	return render_template('index.html')





if __name__ == '__main__':
	#app.run(host="0.0.0.0", port=80)
	app.run(debug="True")