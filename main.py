from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO, emit
import random
from string import ascii_uppercase
import bcrypt
import os
import json
from server_crypto.ecdh import ecdh, Point
from server_crypto.chacha import ChaCha

server_privkey = ecdh.generate_private_key()
server_pubkey = ecdh.generate_public_key(server_privkey)

USERS_FILE = 'db/users.json'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
socketio = SocketIO(app, async_mode='eventlet')

rooms = {}
ROOM_CODE_LEN = 4

def generate_unique_room_code(length):
    """Generates random code of capital letters with this length."""
    while True:
        code = ''
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break

    return code


def hash_password(password):
    """Hash password with bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


def check_password(password, hashed):
    """
    Checks if the hash of the entered password is the same as 
    the hash of the saved password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
 

def load_users():
    """Loads all of the users saved in the json file"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    """
    Updates the users json file with a new updated users.
    :param users: (dict) Usernames as keys and hashed passwords as values.
    """
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)


def register(username, password):
    """Adds new user to the json file if it does not already exists."""
    users = load_users()
    if username in users:
        return "username already exists."
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = hashed.decode()
    save_users(users)
    return "User registered successfully."


def login_user(username, password):
    """Login the user if the username and password exist in the users json file."""
    users = load_users()
    if username not in users:
        return "username not found."
    stored_hash = users[username].encode()
    if bcrypt.checkpw(password.encode(), stored_hash):
        return "Login successful."
    else:
        return "Invalid password."


@app.route('/')
def start():
    if session.get('user') is None:
        return redirect(url_for('login'))
    else:
        return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('room', None)
    session.pop('name', None)
    session.pop('user', None)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error="Please fill in all fields.")

        result = login_user(username, password)

        if result == "Login successful.":
            session['user'] = username
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error=result)

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    session.pop('room', None)
    session.pop('name', None)
    session.pop('user', None)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            return render_template('register.html', error='Please fill in all fields.')

        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

        result = register(username, password)
        if result == "User registered successfully.":
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error=result)

    return render_template('register.html')


@app.route('/home', methods=['GET', 'POST'])
def home():
    """From home page you can join a room or create a room."""
    session.pop('room', None)
    session.pop('name', None)
    if session.get('user') is None:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        code = request.form.get('code').upper()
        join = request.form.get('join', False)
        create = request.form.get('create', False)
        logout = request.form.get('logout', False)
        
        if logout != False:
            session.clear()
            return redirect(url_for('login'))

        if not name:
            return render_template('home.html', 
                                   error='Please enter a name.', 
                                   code=code, 
                                   name=name)
        
        if len(name) > 25:
            return render_template('home.html', 
                                   error='Name is more then 25 characters.', 
                                   code=code, 
                                   name=name)

        if join != False and not code:
            return render_template('home.html', 
                                   error='Please enter a room code to join.', 
                                   code=code, 
                                   name=name)

        room = code
        if create != False:
            room = generate_unique_room_code(ROOM_CODE_LEN)
            while room in rooms:
                room = generate_unique_room_code(ROOM_CODE_LEN)
            rooms[room] = {'clients': {}, 'names': set()}
        elif code not in rooms:
            return render_template('home.html', 
                                   error='Room does not exist.', 
                                   code=code, 
                                   name=name)

        session['room'] = room
        session['name'] = name

        if name in rooms[room]['names']:
            return render_template('home.html', 
                                   error='This name is already in use in the room.', 
                                   code=code, 
                                   name=name)
        
        rooms[room]['names'].add(name)
        return redirect(url_for('room'))

    return render_template('home.html')


@app.route('/room')
def room():
    room = session.get('room')

    if session.get('user') is None:
        return redirect(url_for('login'))
    
    if room is None or session.get('name') is None or room not in rooms:
        return redirect(url_for('home'))
    
    return render_template('room.html', code=room)


@socketio.on('publicKey')
def share_pubkey(data):
    """
    This function is responsible for the key exchange with the client and the server.
    The client send his public key and the server sends back his own public key so they
    both can generate their shared key.
    The server saves the shared key in a dictionary, with the sid as the key and the 
    ChaCha object of the client (with that sid) as the value.

    :param data: (dict) With the clients public key (x and y).
    """
    room = session.get('room')
    client_sid = request.sid
    client_pub = data['client_publicKey']
      
    # Compute shared key
    shared_key = ecdh.generate_shared_key(
        server_privkey, 
        Point(int(client_pub['x']), int(client_pub['y']), ecdh)
    )

    # Send server's public key back to client
    server_pubkey_dict = {
        'server_publicKey': {
            'x': str(server_pubkey.x),
            'y': str(server_pubkey.y)
        }
    }
    emit('server_publicKey', server_pubkey_dict, to=client_sid)
    # Save the shared key
    rooms[room]['clients'][client_sid] = ChaCha(shared_key, 
                                                ecdh.generate_shared_nonce(shared_key))


@socketio.on('message')
def message(data):
    """
    This function is responsible for recieving an encrypted message from a client, decrypting it, 
    and sending their message ecrypted to each other client in the room.
    """
    room = session.get('room')
    name = session.get('name')
    client_sid = request.sid
    if room not in rooms or client_sid not in rooms[room]['clients'] or name is None:
        return
    
    # Get the client ChaCha object
    chacha_sender = rooms[room]['clients'][client_sid]

    # Decrypt the message
    try:
        plaintext = chacha_sender.decrypt(data['data'])
    except Exception:
        plaintext = "[decryption error]"
    
    # Send it encrypted to each client with their own shared key
    for sid, chacha_client in rooms[room]['clients'].items():
        if sid == client_sid:
            continue
        try:
            encrypted = chacha_client.encrypt(plaintext)
        except Exception:
            encrypted = ""
        send({'name': name, 'encrypted': encrypted}, to=sid)


@socketio.on('connect')
def connect():
    """
    This function is responsible for when a client starts a socket with the server,
    which is when he joins a room. It adds the client to the room in the rooms dictionary
    and sends the 'has joined the room' message to each client in the room.
    """
    room = session.get('room')
    name = session.get('name')
    if not room or not name:
        return
    if room not in rooms:
        return

    rooms[room]['names'].add(name)

    plaintext = 'has joined the room'
    for sid, chacha_client in rooms[room].get('clients', {}).items():
        try:
            encrypted = chacha_client.encrypt(plaintext)
        except Exception:
            encrypted = ''
        send({'name': name, 'encrypted': encrypted}, to=sid)


@socketio.on('disconnect')
def disconnect():
    """
    This function is responsible for when a client disconnects from the socket, 
    which is when he leaves the room. It deletes the client from the rooms dictionary
    and send the 'has left the room message to each other client in the room.
    If the room is empty it deletes the room.
    """
    room = session.get('room')
    name = session.get('name')
    client_sid = request.sid

    if room in rooms:
        rooms[room]['names'].remove(name)
        if len(rooms[room]['names']) == 0:
            del rooms[room]
        else:
            rooms[room]['clients'].pop(client_sid, None)

            plaintext = 'has left the room'
            for sid, chacha_recipient in rooms[room].get('clients', {}).items():
                try:
                    encrypted = chacha_recipient.encrypt(plaintext)
                except Exception:
                    encrypted = ""
                send({'name': name, 'encrypted': encrypted}, to=sid)


if __name__ == '__main__':
    # For running it locali with debuging:
    # socketio.run(app, debug=True)
    socketio.run(app, host='0.0.0.0', port=5000, keyfile='key.pem', certfile='cert.pem')
    # If you run it with host='0.0.0.0':
    # To enter the website: https://type_your_ipv4_here:5000
    # remember to type: **https**
    # and not http
