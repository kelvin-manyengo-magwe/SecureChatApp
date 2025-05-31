from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key' # Change this!
# For Flask-SocketIO, use eventlet for production, but built-in dev server works for testing
socketio = SocketIO(app, async_mode='eventlet') # using eventlet

# Store users - for a quick demo, an in-memory dictionary
# In a real app, this would be a database
# {session_id: username}
users = {}

@app.route('/')
def index():
    """Serve the main chat page."""
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    """Client connects."""
    print(f"Client connected: {request.sid}")
    # We'll ask for username via a separate 'join' event from client

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnects."""
    username = users.pop(request.sid, 'Someone')
    print(f"Client disconnected: {username} ({request.sid})")
    emit('user_status', {'username': username, 'status': 'left'}, broadcast=True)

@socketio.on('join')
def handle_join(data):
    """Client joins with a username."""
    username = data.get('username', 'Anonymous')
    if not username.strip(): # Basic validation
        username = 'Anonymous'

    users[request.sid] = username
    print(f"User {username} joined with session ID {request.sid}")
    # Join a default room (e.g., 'chat_room') for simplicity
    join_room('chat_room')
    emit('user_status', {'username': username, 'status': 'joined'}, room='chat_room')
    emit('system_message', {'msg': f"{username} has joined the chat!"}, room='chat_room')


@socketio.on('chat_message')
def handle_chat_message(data):
    """Client sends a chat message."""
    username = users.get(request.sid, 'Unknown User')
    message_text = data.get('msg', '')

    if not message_text.strip(): # Don't send empty messages
        return

    print(f"Message from {username}: {message_text}")
    emit('new_message', {
        'username': username,
        'msg': message_text
    }, room='chat_room') # Broadcast to everyone in the room


if __name__ == '__main__':
    print("Starting server on https://localhost:5000")
    print("IMPORTANT: You'll likely need to accept a browser security warning for the self-signed certificate.")

    # When using eventlet, pass certfile and keyfile directly
    socketio.run(app, host='0.0.0.0', port=5000,
                 certfile='server.crt',
                 keyfile='server.key',
                 debug=True, # You can keep debug=True for development
                 use_reloader=False) # Try with reloader disabled first for stability
                                    # You can experiment with True later
