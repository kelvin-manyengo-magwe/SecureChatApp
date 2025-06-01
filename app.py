from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from functools import wraps
import datetime # For audit log timestamps

app = Flask(__name__)
# IMPORTANT: Change this in a real application! Used for session cookie integrity and more.
app.config['SECRET_KEY'] = 'a_much_better_super_secret_random_key_12345!'
# Configure session cookie for security (Flask does a good job by default over HTTPS)
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitigates CSRF to some extent

socketio = SocketIO(app, async_mode='eventlet')

# --- DEMO User Data & State ---
# PASSWORDS SHOULD BE HASHED in a real app (e.g., werkzeug.security.generate_password_hash)
DEMO_USERS = {
    "alice": {"password": "password_student", "role": "student", "display_name": "Alice (Student)"},
    "bob": {"password": "password_teacher", "role": "teacher", "display_name": "Mr. Bob (Teacher)"},
    "charlie": {"password": "password_student2", "role": "student", "display_name": "Charlie (Student)"},
    "admin": {"password": "password_admin", "role": "administrator", "display_name": "Admin Principal"}
}
AVAILABLE_ROOMS = ["General Chat", "Math Class (Sec A)", "Teachers Lounge"]

# In-memory state (for demo - a real app would use a DB or Redis)
# {room_name: {user_sid: {"muted": True/False, "username": "username"} }}
room_user_states = {room: {} for room in AVAILABLE_ROOMS}
# {user_sid: {"username": username, "display_name": display_name, "role": role, "current_room": room_name }}
connected_users_info = {}


# --- Audit Logging ---
def audit_log(event_type, message, username="System"):
    timestamp = datetime.datetime.now().isoformat()
    log_message = f"AUDIT_LOG [{timestamp}] User: {username}, Event: {event_type}, Details: {message}"
    print(log_message)
    # In a real system, this would write to a dedicated, secure log file or service.

# --- Helper Functions & Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            audit_log("Access Denied", f"Unauthorized access attempt to {request.path}")
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_record = DEMO_USERS.get(username)

        # NOTE: PLAIN TEXT PASSWORD COMPARISON - FOR DEMO ONLY!
        # In production, compare HASHED passwords:
        # from werkzeug.security import check_password_hash
        # if user_record and check_password_hash(user_record['hashed_password'], password):
        if user_record and user_record['password'] == password:
            session['username'] = username
            session['role'] = user_record['role']
            session['display_name'] = user_record['display_name']
            audit_log("Login Success", f"User logged in successfully.", username)
            flash(f"Welcome, {user_record['display_name']}!", "success")
            return redirect(url_for('chat_page'))
        else:
            audit_log("Login Failed", f"Failed login attempt for username: {username}", "N/A" if not username else username)
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    audit_log("Logout", "User logged out.", username)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def chat_page():
    return render_template('index.html',
                           rooms=AVAILABLE_ROOMS,
                           user_role=session.get('role', 'student'),
                           current_username=session.get('username'))


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        audit_log("Socket Auth Fail", f"Unauthorized Socket.IO connection attempt SID: {request.sid}")
        return False # Reject connection

    username = session['username']
    display_name = session['display_name']
    role = session['role']

    connected_users_info[request.sid] = {
        "username": username,
        "display_name": display_name,
        "role": role,
        "current_room": None # Will be set on 'join_room'
    }
    audit_log("Socket Connect", f"User connected via Socket.IO. SID: {request.sid}", username)
    print(f"Client connected: {display_name} ({username}), SID: {request.sid}")

    # Auto-join default room.
    # User must explicitly join to interact fully. We send available rooms.
    emit('connection_ack', {'sid': request.sid, 'rooms': AVAILABLE_ROOMS})

    # For Admin: Update connected users list
    if role == "administrator":
        emit('admin_user_list_update', get_admin_user_list_data())


def get_admin_user_list_data():
    """ Helper to format user list for admin. """
    users_list = []
    for sid, info in connected_users_info.items():
        users_list.append({
            'sid': sid,
            'display_name': info['display_name'],
            'username': info['username'],
            'role': info['role'],
            'current_room': info.get('current_room', 'N/A')
        })
    return users_list


@socketio.on('disconnect')
def handle_disconnect():
    user_info = connected_users_info.pop(request.sid, None)
    if user_info:
        username = user_info['username']
        display_name = user_info['display_name']
        current_room = user_info.get('current_room')
        audit_log("Socket Disconnect", f"User disconnected. SID: {request.sid}", username)
        print(f"Client disconnected: {display_name} ({username}), SID: {request.sid}")

        if current_room and current_room in room_user_states:
            room_user_states[current_room].pop(request.sid, None)
            emit('system_message',
                 {'msg': f"{display_name} has disconnected."},
                 room=current_room)

        # For Admin: Update connected users list
        # Check if any admin is connected to send this update. A bit naive.
        for sid, info_conn in connected_users_info.items():
            if info_conn['role'] == "administrator":
                 socketio.emit('admin_user_list_update', get_admin_user_list_data(), room=sid)
    else:
        audit_log("Socket Disconnect Unknown", f"Unknown client disconnected. SID: {request.sid}")

@socketio.on('join_room_request') # Changed from 'join_room' to be more explicit
def handle_join_room_request(data):
    if 'username' not in session:
        emit('error_msg', {'msg': 'Authentication error. Please re-login.'})
        return

    room_name = data.get('room')
    user_sid = request.sid
    current_user_info = connected_users_info.get(user_sid)
    if not current_user_info: # Should not happen if connect logic is fine
        emit('error_msg', {'msg': 'Session error. Please re-login.'})
        return

    current_user_role = current_user_info['role']
    display_name = current_user_info['display_name']

    # RBAC: Check if user is allowed in the room
    if room_name == "Teachers Lounge" and current_user_role not in ["teacher", "administrator"]:
        audit_log("Join Room Denied", f"User tried to join restricted room '{room_name}'.", display_name)
        emit('error_msg', {'msg': f"You are not authorized to join '{room_name}'."})
        return

    if room_name not in AVAILABLE_ROOMS:
        audit_log("Join Room Denied", f"User tried to join non-existent room '{room_name}'.", display_name)
        emit('error_msg', {'msg': f"Room '{room_name}' does not exist."})
        return

    previous_room = current_user_info.get('current_room')
    if previous_room and previous_room != room_name:
        leave_room(previous_room)
        if previous_room in room_user_states: # cleanup state
            room_user_states[previous_room].pop(user_sid, None)
        emit('system_message', {'msg': f"{display_name} has left '{previous_room}'."}, room=previous_room)

    join_room(room_name)
    current_user_info['current_room'] = room_name

    if room_name not in room_user_states: # Initialize room if new
        room_user_states[room_name] = {}
    room_user_states[room_name][user_sid] = {"muted": False, "username": current_user_info['username']}

    audit_log("Join Room", f"User joined room '{room_name}'.", display_name)
    print(f"{display_name} joined {room_name}")
    emit('system_message', {'msg': f"{display_name} has joined '{room_name}'."}, room=room_name)
    emit('joined_room_ack', {'room': room_name, 'is_muted': room_user_states[room_name][user_sid]["muted"]})

    # For Admin: Update connected users list as current_room changed
    for sid, info_conn in connected_users_info.items():
        if info_conn['role'] == "administrator":
            socketio.emit('admin_user_list_update', get_admin_user_list_data(), room=sid)


@socketio.on('chat_message')
def handle_chat_message(data):
    if 'username' not in session: # Session check
        emit('error_msg', {'msg': 'Authentication error. Please re-login.'})
        return

    user_sid = request.sid
    current_user_info = connected_users_info.get(user_sid)
    if not current_user_info or not current_user_info.get('current_room'):
        emit('error_msg', {'msg': 'You are not currently in a room.'})
        return

    target_room = current_user_info['current_room']

    # Check Mute Status
    if target_room in room_user_states and \
       user_sid in room_user_states[target_room] and \
       room_user_states[target_room][user_sid].get("muted", False):
        audit_log("Message Blocked", f"User tried to send message while muted in '{target_room}'.", current_user_info['display_name'])
        emit('error_msg', {'msg': 'You are currently muted in this room.'})
        return

    # Basic Input Sanitization (Conceptual - Flask/Jinja autoescapes in templates)
    # For messages directly injected into JS or stored, explicit sanitization is critical.
    # from markupsafe import escape
    # message_text = escape(data.get('msg', '').strip())
    message_text = data.get('msg', '').strip() # Rely on client-side rendering to be safe for this PoC

    if not message_text: return

    audit_log("Chat Message Sent", f"Room: {target_room}, Message: '{message_text[:30]}...'", current_user_info['display_name'])
    emit('new_message', {
        'username': current_user_info['display_name'],
        'msg': message_text, # Send original for client-side handling
        'role': current_user_info['role']
    }, room=target_room)


@socketio.on('create_room_request')
def handle_create_room_request(data):
    if 'username' not in session: return
    current_user_info = connected_users_info.get(request.sid)
    if not current_user_info: return

    if current_user_info['role'] not in ['teacher', 'administrator']:
        audit_log("Create Room Denied", "User lacks permission.", current_user_info['display_name'])
        emit('error_msg', {'msg': 'You do not have permission to create rooms.'})
        return

    new_room_name = data.get('room_name', '').strip()
    if not new_room_name:
        emit('error_msg', {'msg': 'Room name cannot be empty.'})
        return
    if len(new_room_name) > 50: # Example validation
        emit('error_msg', {'msg': 'Room name too long (max 50 chars).'})
        return

    if new_room_name in AVAILABLE_ROOMS:
        emit('error_msg', {'msg': f"Room '{new_room_name}' already exists."})
        return

    AVAILABLE_ROOMS.append(new_room_name)
    room_user_states[new_room_name] = {} # Initialize state for new room
    audit_log("Room Created", f"New room '{new_room_name}' created.", current_user_info['display_name'])

    socketio.emit('new_room_available', {'room_name': new_room_name, 'creator': current_user_info['display_name']})
    emit('system_message', {'msg': f"You created room: '{new_room_name}'."})

# --- Teacher/Admin Specific Actions ---
@socketio.on('mute_user_request')
def handle_mute_user_request(data):
    if 'username' not in session: return
    requesting_user_info = connected_users_info.get(request.sid)
    if not requesting_user_info: return

    if requesting_user_info['role'] not in ['teacher', 'administrator']:
        audit_log("Mute Denied", "User lacks permission for mute.", requesting_user_info['display_name'])
        emit('error_msg', {'msg': 'You do not have permission to mute users.'})
        return

    target_username = data.get('username_to_mute') # Send username, not SID, for UX
    target_room = requesting_user_info.get('current_room')

    if not target_room or not target_username:
        emit('error_msg', {'msg': 'Missing target user or room info.'})
        return

    target_user_sid = None
    target_user_display_name = None
    for sid, info in connected_users_info.items():
        if info['username'] == target_username and info.get('current_room') == target_room :
            # RBAC: Teacher cannot mute another teacher or admin. Admin can mute anyone but self (or other admins for simplicity)
            if requesting_user_info['role'] == 'teacher' and info['role'] in ['teacher', 'administrator']:
                 audit_log("Mute Denied", f"Teacher tried to mute non-student/privileged user '{info['display_name']}'.", requesting_user_info['display_name'])
                 emit('error_msg', {'msg': f"Teachers can only mute students."})
                 return
            if info['username'] == requesting_user_info['username']: # Can't mute self
                 emit('error_msg', {'msg': f"You cannot mute yourself."})
                 return

            target_user_sid = sid
            target_user_display_name = info['display_name']
            break

    if not target_user_sid:
        emit('error_msg', {'msg': f"User '{target_username}' not found in room '{target_room}'."})
        return

    if target_room in room_user_states and target_user_sid in room_user_states[target_room]:
        is_currently_muted = room_user_states[target_room][target_user_sid].get("muted", False)
        new_mute_state = not is_currently_muted # Toggle mute
        room_user_states[target_room][target_user_sid]["muted"] = new_mute_state

        action_verb = "muted" if new_mute_state else "unmuted"
        audit_log("User Mute Toggled", f"User '{target_user_display_name}' was {action_verb} in room '{target_room}'.", requesting_user_info['display_name'])

        # Notify the target user
        socketio.emit('mute_status_update', {'room': target_room, 'is_muted': new_mute_state}, room=target_user_sid)
        # Notify everyone in the room (system message)
        emit('system_message', {'msg': f"{target_user_display_name} has been {action_verb} by {requesting_user_info['display_name']}."}, room=target_room)
    else:
        emit('error_msg', {'msg': 'Error updating mute state.'})


if __name__ == '__main__':
    print("Starting server on https://localhost:5000")
    print("DEMO PASSWORDS (plain text - DO NOT USE FOR REAL APPS):")
    for uname, udata in DEMO_USERS.items():
        print(f"  {uname} / {udata['password']} (Role: {udata['role']})")
    print("IMPORTANT: You'll likely need to accept a browser security warning for the self-signed certificate.")
    socketio.run(app, host='0.0.0.0', port=5000,
                 certfile='server.crt',
                 keyfile='server.key',
                 debug=True,
                 use_reloader=False)
