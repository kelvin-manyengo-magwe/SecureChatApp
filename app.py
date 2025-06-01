from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from functools import wraps # For login_required decorator

app = Flask(__name__)
# IMPORTANT: Change this in a real application! This is for secure session cookies.
app.config['SECRET_KEY'] = 'your_really_strong_random_secret_key_shhhh!'
socketio = SocketIO(app, async_mode='eventlet')

# --- DEMO User Data (Replace with a database in a real app) ---
# Passwords should be HASHED in a real app (e.g., using werkzeug.security.generate_password_hash)
DEMO_USERS = {
    "alice": {"password": "password_student", "role": "student", "display_name": "Alice (Student)"},
    "bob": {"password": "password_teacher", "role": "teacher", "display_name": "Mr. Bob (Teacher)"},
    "admin": {"password": "password_admin", "role": "administrator", "display_name": "Admin Principal"}
}

# --- DEMO Room Data (In a real app, this would be dynamic and in a DB) ---
AVAILABLE_ROOMS = ["General Chat", "Math Class (Sec A)", "Teachers Lounge"]

# --- Helper Functions & Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
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

        user = DEMO_USERS.get(username)
        # IMPORTANT: In real app, compare HASHED passwords
        if user and user['password'] == password:
            session['username'] = username
            session['role'] = user['role']
            session['display_name'] = user['display_name']
            flash(f"Welcome, {user['display_name']}!", "success")
            return redirect(url_for('chat_page'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def chat_page():
    """Serve the main chat page."""
    # Pass available rooms and user role to the template for dynamic UI
    return render_template('index.html',
                           rooms=AVAILABLE_ROOMS,
                           user_role=session.get('role', 'student'))

# --- SocketIO Event Handlers (NEED TO BE AWARE OF AUTH/SESSION) ---
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        # This happens if someone tries to establish a SocketIO connection without a Flask session
        # This check is a bit tricky as HTTP session isn't directly available in connect scope by default
        # for ALL socketio transports in a straightforward way without custom middleware.
        # Flask-SocketIO usually handles this better if you protect the HTML page serving the JS.
        print(f"Unauthorized Socket.IO connection attempt. SID: {request.sid}")
        # disconnect(request.sid) # Force disconnect if no valid session
        # For now, we rely on the HTML page being login_required
        # A more robust way would involve passing a token or using connect_args.
        return False # Reject connection explicitly if not authenticated.

    print(f"Client connected: {session['display_name']} ({session['username']}), SID: {request.sid}")
    # Automatically join a default room or wait for client to emit 'join_room'
    default_room = AVAILABLE_ROOMS[0]
    join_room(default_room) # Join the default room upon connection
    emit('system_message',
         {'msg': f"{session['display_name']} has connected to '{default_room}'."},
         room=default_room)

@socketio.on('disconnect')
def handle_disconnect():
    if 'display_name' in session: # Check if session was properly established
        print(f"Client disconnected: {session['display_name']} ({session['username']}), SID: {request.sid}")
        # Notify rooms the user was in (this needs more complex room tracking)
        # For simplicity, let's assume they were in 'General Chat' if not tracked better
        active_room = session.get('current_room', AVAILABLE_ROOMS[0]) # Use a session var if set
        emit('system_message',
             {'msg': f"{session['display_name']} has disconnected."},
             room=active_room)
    else:
        print(f"Client disconnected (no session info). SID: {request.sid}")


@socketio.on('join_room')
def handle_join_room(data):
    if 'username' not in session:
        return emit('error_msg', {'msg': 'Authentication required.'})

    room_name = data.get('room')
    current_user_role = session['role']
    display_name = session['display_name']

    # RBAC: Check if user is allowed in the room
    # Example: Teachers Lounge only for 'teacher' or 'administrator'
    if room_name == "Teachers Lounge" and current_user_role not in ["teacher", "administrator"]:
        emit('error_msg', {'msg': f"You are not authorized to join '{room_name}'."})
        return

    if room_name not in AVAILABLE_ROOMS:
        emit('error_msg', {'msg': f"Room '{room_name}' does not exist."})
        return

    # Leave previous room (if any, simple example: assume only one room at a time)
    previous_room = session.get('current_room')
    if previous_room and previous_room != room_name:
        leave_room(previous_room)
        emit('system_message', {'msg': f"{display_name} has left '{previous_room}'."}, room=previous_room)
        print(f"{display_name} left {previous_room}")

    join_room(room_name)
    session['current_room'] = room_name # Store current room in session
    print(f"{display_name} joined {room_name}")
    emit('system_message', {'msg': f"{display_name} has joined '{room_name}'."}, room=room_name)
    emit('joined_room_ack', {'room': room_name}) # Acknowledge to client

@socketio.on('chat_message')
def handle_chat_message(data):
    if 'username' not in session:
        return emit('error_msg', {'msg': 'Authentication required to send messages.'})

    message_text = data.get('msg', '').strip()
    target_room = session.get('current_room', AVAILABLE_ROOMS[0]) # Send to current room

    if not message_text:
        return # Don't send empty messages

    print(f"Message from {session['display_name']} in room {target_room}: {message_text}")
    emit('new_message', {
        'username': session['display_name'], # Use display name
        'msg': message_text,
        'role': session['role'] # Send role for potential UI differentiation
    }, room=target_room)


@socketio.on('create_room_request') # For teachers/admins
def handle_create_room_request(data):
    if 'username' not in session:
        return emit('error_msg', {'msg': 'Authentication required.'})

    current_user_role = session['role']
    if current_user_role not in ['teacher', 'administrator']:
        return emit('error_msg', {'msg': 'You do not have permission to create rooms.'})

    new_room_name = data.get('room_name', '').strip()
    if not new_room_name:
        return emit('error_msg', {'msg': 'Room name cannot be empty.'})

    if new_room_name in AVAILABLE_ROOMS:
        return emit('error_msg', {'msg': f"Room '{new_room_name}' already exists."})

    AVAILABLE_ROOMS.append(new_room_name) # Add to demo list
    print(f"Room '{new_room_name}' created by {session['display_name']}")

    # Notify all clients (or just relevant ones) about the new room
    socketio.emit('new_room_available', {'room_name': new_room_name, 'creator': session['display_name']})
    emit('system_message', {'msg': f"You created room: '{new_room_name}'."}) # Ack to creator

if __name__ == '__main__':
    print("Starting server on https://localhost:5000")
    print("IMPORTANT: You'll likely need to accept a browser security warning for the self-signed certificate.")
    socketio.run(app, host='0.0.0.0', port=5000,
                 certfile='server.crt',
                 keyfile='server.key',
                 debug=True,
                 use_reloader=False) # Keep reloader false with eventlet typically
