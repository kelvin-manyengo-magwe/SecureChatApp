from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room # Removed disconnect as we use return False now
from flask_talisman import Talisman
from functools import wraps
import datetime
import uuid
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_absolute_best_ultra_secret_key_98765_for_real_this_time!' # CHANGE THIS!
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitigates CSRF

# --- Audit Logging (Defined Early) ---
def audit_log(event_type, message, username="System"):
    timestamp = datetime.datetime.now().isoformat()
    log_message = f"AUDIT_LOG [{timestamp}] User: {username}, Event: {event_type}, Details: {message}"
    print(log_message)
    # In a real system, this would write to a dedicated, secure log file or service.

# --- Helper Functions & Decorators (Defined Early) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            audit_log("Access Denied", f"Unauthorized access attempt to {request.path} by IP: {request.remote_addr}")
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Content Security Policy (CSP) ---
# Refer to previous detailed CSP, this is a simplified version. Adjust as needed.
csp = {
    'default-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com' # For Socket.IO client
    ],
    'script-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com',
        '\'unsafe-inline\'' # Ideally remove for production
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'' # Ideally remove for production
    ],
    'connect-src': ['\'self\''], # For WebSockets from same origin
    'img-src': ['\'self\'', 'data:'],
    'object-src': '\'none\'',
    'frame-ancestors': '\'none\''
}
# force_https=True when not using permanent for dev might be easier if cert is self-signed.
# force_https_permanent=True in production with a valid CA cert.
talisman = Talisman(app, content_security_policy=csp, force_https=True, session_cookie_secure=True, session_cookie_http_only=True, session_cookie_samesite='Lax')

socketio = SocketIO(app, async_mode='eventlet')

# --- "Data at Rest" Encryption Demo ---
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)
audit_log("System Startup", f"DEMO encryption key generated (ephemeral): {ENCRYPTION_KEY.decode()[:10]}...", "System")

def encrypt_data(data_str):
    if not isinstance(data_str, str): data_str = str(data_str) # Ensure it's a string
    if not data_str: return None
    return cipher_suite.encrypt(data_str.encode()).decode()

def decrypt_data(encrypted_data_str):
    if not encrypted_data_str: return None
    try:
        return cipher_suite.decrypt(encrypted_data_str.encode()).decode()
    except Exception as e:
        audit_log("Decryption Error", f"Failed to decrypt data. Error: {e}", "System")
        return "[DECRYPTION FAILED - INVALID TOKEN]"

# --- DEMO User Data & State ---
DEMO_USERS = {
    "alice": {"password": "password_student", "role": "student", "display_name": "Alice (Student)"},
    "bob": {"password": "password_teacher", "role": "teacher", "display_name": "Mr. Bob (Teacher)"},
    "charlie": {"password": "password_student2", "role": "student", "display_name": "Charlie (Student)"},
    "admin": {"password": "password_admin", "role": "administrator", "display_name": "Admin Principal"}
}
AVAILABLE_ROOMS = ["General Chat", "Math Class (Sec A)", "Teachers Lounge"]
chat_messages_store = {room: [] for room in AVAILABLE_ROOMS} # {room: [{'id', 'username', 'actual_username', 'role', 'timestamp', 'encrypted_msg', 'deleted'}, ...]}
room_user_states = {room: {} for room in AVAILABLE_ROOMS}    # {room: {sid: {'muted', 'username'}}}
connected_users_info = {} # {sid: {'username', 'display_name', 'role', 'current_room'}}

# --- Login Rate Limiting Demo ---
LOGIN_ATTEMPTS = {} # {ip_address: {'count': N, 'last_attempt': datetime}}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = datetime.timedelta(minutes=5)

def get_admin_user_list_data():
    users_list = []
    for sid_key, info in connected_users_info.items(): # Renamed sid to sid_key to avoid conflict
        users_list.append({
            'sid': sid_key, # Send the actual SID for potential future admin actions (kick/ban - not implemented)
            'display_name': info['display_name'],
            'username': info['username'],
            'role': info['role'],
            'current_room': info.get('current_room', 'N/A')
        })
    return users_list

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr
    current_time = datetime.datetime.now()

    if client_ip in LOGIN_ATTEMPTS:
        attempts_info = LOGIN_ATTEMPTS[client_ip]
        if current_time - attempts_info['last_attempt'] > LOGIN_ATTEMPT_WINDOW:
            LOGIN_ATTEMPTS.pop(client_ip, None)
        elif attempts_info['count'] >= MAX_LOGIN_ATTEMPTS:
            audit_log("Login Lockout", f"IP {client_ip} locked out.", client_ip) # Use client_ip as "username" for this log
            flash(f"Too many failed login attempts. Please try again in {int(LOGIN_ATTEMPT_WINDOW.total_seconds() // 60)} minutes.", "danger")
            return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_record = DEMO_USERS.get(username)

        # Production: Use HASHED password comparison
        if user_record and user_record['password'] == password:
            session['username'] = username
            session['role'] = user_record['role']
            session['display_name'] = user_record['display_name']
            LOGIN_ATTEMPTS.pop(client_ip, None)
            audit_log("Login Success", "User logged in successfully.", username)
            flash(f"Welcome, {user_record['display_name']}!", "success")
            return redirect(url_for('chat_page'))
        else:
            if client_ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[client_ip] = {'count': 0, 'last_attempt': current_time}
            LOGIN_ATTEMPTS[client_ip]['count'] += 1
            LOGIN_ATTEMPTS[client_ip]['last_attempt'] = current_time

            remaining_attempts = MAX_LOGIN_ATTEMPTS - LOGIN_ATTEMPTS[client_ip]['count']
            audit_log("Login Failed", f"Attempt for user: {username or '[empty]'}. IP: {client_ip}. Rem: {max(0, remaining_attempts)}", username or client_ip)
            flash_msg = "Invalid username or password."
            if 0 <= remaining_attempts < MAX_LOGIN_ATTEMPTS -1 : # Provide specific remaining count if few left
                 flash_msg += f" {remaining_attempts} attempts remaining before lockout."
            flash(flash_msg, "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    username_in_session = session.get('username', 'Unknown_User') # Get username before clearing
    audit_log("Logout", "User logged out.", username_in_session)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def chat_page():
    return render_template('index.html',
                           rooms=AVAILABLE_ROOMS, # Pass all rooms
                           user_role=session.get('role', 'student'),
                           current_username=session.get('username'))


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        audit_log("Socket Auth Fail", f"Unauthorized SID: {request.sid}, IP: {request.remote_addr}")
        return False # Explicitly reject connection

    username = session['username']
    display_name = session['display_name']
    role = session['role']

    connected_users_info[request.sid] = {
        "username": username, "display_name": display_name, "role": role, "current_room": None
    }
    audit_log("Socket Connect", f"User connected. SID: {request.sid}", username)
    emit('connection_ack', {'sid': request.sid, 'all_rooms': AVAILABLE_ROOMS}) # Send all rooms to client
    # For Admin: Update connected users list if an admin is connecting or already connected
    if role == "administrator":
        emit('admin_user_list_update', get_admin_user_list_data()) # For the connecting admin
    for sid_admin, info_admin in connected_users_info.items(): # For already connected admins
        if info_admin['role'] == "administrator" and sid_admin != request.sid:
            socketio.emit('admin_user_list_update', get_admin_user_list_data(), room=sid_admin)

@socketio.on('disconnect')
def handle_disconnect():
    user_info = connected_users_info.pop(request.sid, None)
    if user_info:
        username = user_info['username']
        display_name = user_info['display_name']
        current_room = user_info.get('current_room')
        audit_log("Socket Disconnect", f"User disconnected. SID: {request.sid}", username)

        if current_room and current_room in room_user_states:
            if request.sid in room_user_states[current_room]:
                 room_user_states[current_room].pop(request.sid, None)
            emit('system_message', {'msg': f"{display_name} has disconnected."}, room=current_room)

        for sid_admin, info_admin in connected_users_info.items(): # Update any connected admins
            if info_admin['role'] == "administrator":
                 socketio.emit('admin_user_list_update', get_admin_user_list_data(), room=sid_admin)
    else:
        audit_log("Socket Disconnect Unknown", f"Unknown SID: {request.sid}, IP: {request.remote_addr}")


@socketio.on('request_past_messages')
def handle_request_past_messages(data):
    if 'username' not in session: return
    room_name = data.get('room')
    if room_name in chat_messages_store:
        decrypted_messages = []
        for msg_data in chat_messages_store[room_name]:
            if not msg_data.get('deleted', False):
                decrypted_messages.append({
                    'id': msg_data['id'], 'username': msg_data['username'],
                    'actual_username': msg_data['actual_username'], 'role': msg_data['role'],
                    'timestamp': msg_data['timestamp'], 'msg': decrypt_data(msg_data['encrypted_msg'])
                })
        emit('past_messages', {'room': room_name, 'messages': decrypted_messages})

@socketio.on('join_room_request')
def handle_join_room_request(data):
    if 'username' not in session: return emit('error_msg', {'msg': 'Auth error.'})
    room_name = data.get('room')
    user_sid = request.sid # Capture before any potential early return
    current_user_info = connected_users_info.get(user_sid) # Use captured SID

    if not current_user_info: return emit('error_msg', {'msg': 'Session error.'})
    current_user_role = current_user_info['role']; display_name = current_user_info['display_name']
    actual_username = current_user_info['username']

    if room_name == "Teachers Lounge" and current_user_role not in ["teacher", "administrator"]:
        audit_log("Join Denied (Perms)", f"'{actual_username}' to room '{room_name}'.", display_name)
        return emit('error_msg', {'msg': f"Not authorized for '{room_name}'."})
    if room_name not in AVAILABLE_ROOMS:
        audit_log("Join Denied (No Room)", f"'{actual_username}' to room '{room_name}'.", display_name)
        return emit('error_msg', {'msg': f"Room '{room_name}' not found."})

    previous_room = current_user_info.get('current_room')
    if previous_room and previous_room != room_name:
        leave_room(previous_room) # SocketIO's leave_room for user_sid
        if previous_room in room_user_states and user_sid in room_user_states[previous_room]:
            room_user_states[previous_room].pop(user_sid, None)
        emit('system_message', {'msg': f"{display_name} has left '{previous_room}'."}, room=previous_room)

    join_room(room_name) # SocketIO's join_room for user_sid
    current_user_info['current_room'] = room_name

    if room_name not in room_user_states: room_user_states[room_name] = {} # Initialize if new
    room_user_states[room_name][user_sid] = {"muted": False, "username": actual_username}

    audit_log("Join Room", f"User '{actual_username}' joined '{room_name}'.", display_name)
    emit('system_message', {'msg': f"{display_name} has joined '{room_name}'."}, room=room_name)
    emit('joined_room_ack', {'room': room_name, 'is_muted': room_user_states[room_name][user_sid]["muted"]})
    handle_request_past_messages({'room': room_name}) # Send history on successful join

    for sid_admin, info_admin in connected_users_info.items(): # Update admin views
        if info_admin['role'] == "administrator":
            socketio.emit('admin_user_list_update', get_admin_user_list_data(), room=sid_admin)

@socketio.on('chat_message')
def handle_chat_message(data):
    if 'username' not in session: return emit('error_msg', {'msg': 'Auth error.'})
    user_sid = request.sid; current_user_info = connected_users_info.get(user_sid)
    if not current_user_info or not current_user_info.get('current_room'):
        return emit('error_msg', {'msg': 'Not in a room.'})

    target_room = current_user_info['current_room']
    if room_user_states.get(target_room, {}).get(user_sid, {}).get("muted", False):
        audit_log("Msg Blocked (Muted)", f"In '{target_room}'.", current_user_info['display_name'])
        return emit('error_msg', {'msg': 'You are muted in this room.'})

    message_text = data.get('msg', '').strip()
    if not message_text: return
    if len(message_text) > 1000: return emit('error_msg', {'msg': 'Message too long (max 1000).'})

    encrypted_msg = encrypt_data(message_text)
    if not encrypted_msg:
        audit_log("Encryption Fail", "Message not sent.", current_user_info['display_name'])
        return emit('error_msg', {'msg': 'Error processing message.'})

    msg_id = str(uuid.uuid4()); timestamp = datetime.datetime.now().isoformat()

    msg_to_store = {
        'id': msg_id, 'username': current_user_info['display_name'],
        'actual_username': current_user_info['username'], 'role': current_user_info['role'],
        'timestamp': timestamp, 'encrypted_msg': encrypted_msg, 'deleted': False
    }
    if target_room not in chat_messages_store: chat_messages_store[target_room] = []
    chat_messages_store[target_room].append(msg_to_store)
    audit_log("Msg Stored (Enc)", f"ID: {msg_id} in '{target_room}'. Enc: {encrypted_msg[:20]}...", current_user_info['display_name'])

    msg_to_client = {
        'id': msg_id, 'username': current_user_info['display_name'],
        'actual_username': current_user_info['username'], 'msg': message_text, # Send plain text
        'role': current_user_info['role'], 'timestamp': timestamp
    }
    emit('new_message', msg_to_client, room=target_room)

@socketio.on('create_room_request')
def handle_create_room_request(data):
    if 'username' not in session: return emit('error_msg', {'msg': 'Auth error.'})
    current_user_info = connected_users_info.get(request.sid)
    if not current_user_info or current_user_info['role'] not in ['teacher', 'administrator']:
        audit_log("Create Room Denied (Perms)", "", current_user_info.get('display_name','N/A'))
        return emit('error_msg', {'msg': 'Permission denied.'})

    new_room_name = data.get('room_name', '').strip()
    if not new_room_name or len(new_room_name) > 50: return emit('error_msg', {'msg': 'Invalid room name.'})
    if new_room_name in AVAILABLE_ROOMS: return emit('error_msg', {'msg': f"Room '{new_room_name}' exists."})

    AVAILABLE_ROOMS.append(new_room_name)
    room_user_states[new_room_name] = {} # Init state
    chat_messages_store[new_room_name] = [] # Init message store
    audit_log("Room Created", f"Name: '{new_room_name}'.", current_user_info['display_name'])
    socketio.emit('new_room_available_update', {'all_rooms': AVAILABLE_ROOMS, 'creator': current_user_info['display_name'], 'new_room_name': new_room_name }) # Send ALL rooms
    emit('system_message', {'msg': f"You created room: '{new_room_name}'."})

@socketio.on('mute_user_request')
def handle_mute_user_request(data):
    if 'username' not in session: return emit('error_msg', {'msg': 'Auth error.'})
    requesting_user_info = connected_users_info.get(request.sid)
    if not requesting_user_info or requesting_user_info['role'] not in ['teacher', 'administrator']:
        audit_log("Mute Denied (Perms)", "", requesting_user_info.get('display_name','N/A'))
        return emit('error_msg', {'msg': 'Permission denied.'})

    target_actual_username = data.get('username_to_mute')
    target_room = requesting_user_info.get('current_room')
    if not target_room or not target_actual_username: return emit('error_msg', {'msg': 'Missing info.'})

    target_user_sid, target_user_display_name, target_user_role = (None, None, None)
    for sid_lookup, info_lookup in connected_users_info.items():
        if info_lookup['username'] == target_actual_username and info_lookup.get('current_room') == target_room:
            target_user_sid, target_user_display_name, target_user_role = sid_lookup, info_lookup['display_name'], info_lookup['role']
            break

    if not target_user_sid:
        audit_log("Mute Target Not Found", f"User '{target_actual_username}' not in '{target_room}'.", requesting_user_info['display_name'])
        return emit('error_msg', {'msg': f"User '{target_actual_username}' not found."})

    if requesting_user_info['role'] == 'teacher' and target_user_role != 'student':
        audit_log("Mute Denied (Role)", f"Teacher muted non-student '{target_user_display_name}'.", requesting_user_info['display_name'])
        return emit('error_msg', {'msg': 'Teachers can only mute students.'})
    # Add more complex rules as needed e.g. admin cannot mute admin.
    if requesting_user_info['username'] == target_actual_username: return emit('error_msg', {'msg': 'Cannot mute yourself.'})


    if target_room in room_user_states and target_user_sid in room_user_states[target_room]:
        current_mute_state = room_user_states[target_room][target_user_sid].get("muted", False)
        new_mute_state = not current_mute_state
        room_user_states[target_room][target_user_sid]["muted"] = new_mute_state
        action = "muted" if new_mute_state else "unmuted"
        audit_log("Mute Toggled", f"'{target_user_display_name}' {action} in '{target_room}'.", requesting_user_info['display_name'])
        socketio.emit('mute_status_update', {'room': target_room, 'is_muted': new_mute_state}, room=target_user_sid)
        emit('system_message', {'msg': f"{target_user_display_name} has been {action} by {requesting_user_info['display_name']}."}, room=target_room)
    else:
        audit_log("Mute State Error", f"No state for '{target_user_display_name}' in '{target_room}'.", requesting_user_info['display_name'])
        emit('error_msg', {'msg': 'Error updating mute state.'})

@socketio.on('delete_message_request')
def handle_delete_message_request(data):
    if 'username' not in session: return emit('error_msg', {'msg': 'Auth error.'})
    requesting_user_info = connected_users_info.get(request.sid)
    if not requesting_user_info: return emit('error_msg', {'msg': 'Session error.'})

    msg_id = data.get('message_id'); room_of_msg = requesting_user_info.get('current_room')
    if not msg_id or not room_of_msg: return emit('error_msg', {'msg': 'Missing info.'})

    found_idx = -1
    if room_of_msg in chat_messages_store:
        for i, msg_data in enumerate(chat_messages_store[room_of_msg]):
            if msg_data['id'] == msg_id and not msg_data.get('deleted', False):
                found_idx = i; break

    if found_idx == -1: return emit('error_msg', {'msg': 'Message not found/already deleted.'})

    msg_to_delete = chat_messages_store[room_of_msg][found_idx]
    can_delete = (requesting_user_info['role'] in ['administrator', 'teacher'] or \
                  msg_to_delete['actual_username'] == requesting_user_info['username'])

    if can_delete:
        chat_messages_store[room_of_msg][found_idx]['deleted'] = True
        decrypted_content_for_log = decrypt_data(msg_to_delete['encrypted_msg']) # For audit
        audit_log("Msg Deleted", f"ID '{msg_id}' in '{room_of_msg}'. Content: '{decrypted_content_for_log[:20]}...'.", requesting_user_info['display_name'])
        emit('message_deleted_ack', {'message_id': msg_id, 'room': room_of_msg}, room=room_of_msg)
    else:
        audit_log("Delete Denied (Perms)", f"Msg ID '{msg_id}'.", requesting_user_info['display_name'])
        emit('error_msg', {'msg': 'Permission denied to delete this message.'})

if __name__ == '__main__':
    print("Starting Secure Chat Server on https://localhost:5000")
    print("DEMO USERS (Username / Password):")
    for uname, udata in DEMO_USERS.items():
        print(f"  {uname} / {udata['password']} (Role: {udata['role']})")
    print("IMPORTANT: Open your browser to https://localhost:5000")
    print("You WILL see a browser security warning for the self-signed certificate. You must accept it to proceed.")
    print("Ensure server.crt and server.key are present in the same directory.")

    socketio.run(app, host='0.0.0.0', port=5000,
                 certfile='server.crt',
                 keyfile='server.key',
                 debug=True,
                 use_reloader=False) # Reloader False is safer with eventlet/gevent and complex state
