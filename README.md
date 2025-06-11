# SecureChatApp :Secure Web Chat for Educational Institutions

**A cybersecurity challenge-based innovation project demonstrating a secure real-time chat application tailored for educational settings.**

## Table of Contents

1.  [Project Description](#project-description)
2.  [Key Features](#key-features)
    *   [Security Features](#security-features)
    *   [Functional Features](#functional-features)
3.  [Technology Stack](#technology-stack)
4.  [Project Structure](#project-structure)
5.  [Setup and Running the Project](#setup-and-running-the-project)
    *   [Prerequisites](#prerequisites)
    *   [Installation & Configuration](#installation--configuration)
    *   [Running the Application](#running-the-application)
6.  [Demonstration & Usage](#demonstration--usage)
7.  [Screenshots (Placeholder)](#screenshots)
8.  [Future Enhancements](#future-enhancements)
9.  [Author](#author)
10. [License](#license)

## 1. Project Description

SecureSchool Connect is a prototype web application designed to provide a secure and controlled real-time communication platform for students, teachers, and administrators within an educational institution. This project was developed as a part of the "IS336: Cybersecurity Challenge-Based Innovation" course, focusing on applying core cybersecurity principles to a real-world problem relevant to the Tanzanian digital landscape.

The application addresses challenges such as data privacy leaks associated with generic messaging platforms, the need for specific educational controls, and defense against common cyber threats. It showcases how features like end-to-end encrypted transit, role-based access control, data-at-rest encryption principles, audit logging, and web security best practices can be integrated into a functional system.

**Specific Educational Context:**
This solution aims to provide a safer, more structured, and policy-compliant alternative for communication in Tanzanian schools, supporting digital transformation initiatives while prioritizing the security and privacy of its users.

## 2. Key Features

### Security Features:

*   **Secure Communication Channel (TLS/SSL):** All client-server communication (HTTP and WebSockets) is encrypted using HTTPS/WSS, protecting data in transit from eavesdropping and tampering. (Uses self-signed certificates for PoC).
*   **User Authentication & Session Management:** Secure login mechanism with Flask sessions. Session cookies are flagged `HttpOnly`, `Secure`, and `SameSite=Lax`.
*   **Login Rate Limiting (Conceptual Logging):** Detects and logs multiple failed login attempts from the same IP address to indicate potential brute-force attacks.
*   **Role-Based Access Control (RBAC):** Distinct roles (`student`, `teacher`, `administrator`) with granular, server-enforced permissions for actions like room creation, user muting, message deletion, and admin panel access.
*   **Data-at-Rest Encryption (Conceptual):** Chat messages are symmetrically encrypted (Fernet - AES based) before being "stored" in an in-memory list, demonstrating the principle of protecting sensitive data even if the underlying storage is compromised. *(Note: PoC uses an ephemeral key).*
*   **Content Security Policy (CSP):** Implemented via Flask-Talisman to mitigate Cross-Site Scripting (XSS) and other injection attacks by restricting resource loading. Other security headers also applied (e.g., `X-Frame-Options` to prevent clickjacking).
*   **Audit Logging:** Critical server-side and user actions (logins, logouts, messages sent/deleted, rooms created/joined, mutes, security alerts) are logged to the console with timestamps and user identifiers, providing a trail for monitoring and incident response.
*   **Input Sanitization Awareness:** Client-side HTML escaping for dynamically rendered content to further prevent XSS. Server-side validation on input lengths.

### Functional Features:

*   **Real-time Messaging:** Users can send and receive messages in chat rooms instantly via WebSockets (Flask-SocketIO).
*   **Multiple Chat Rooms:** Users can join different chat rooms. Teachers/Admins can create new rooms.
*   **User Muting (Teacher/Admin):** Teachers and Administrators can mute/unmute students within a room to manage classroom dynamics.
*   **Message Deletion:** Users can delete their own messages. Teachers/Administrators can delete any message in rooms they manage.
*   **Admin Panel:** Administrators have a view of currently connected users, their roles, and the rooms they are in.
*   **User-Friendly Interface:** A clean web interface showing chat rooms, messages, and user information.

## 3. Technology Stack

*   **Backend:**
    *   Python 3
    *   Flask (Web Framework)
    *   Flask-SocketIO (Real-time WebSocket communication)
    *   Flask-Talisman (Security Headers, HTTPS enforcement)
    *   `cryptography` library (for Fernet encryption)
    *   eventlet (WSGI server for SocketIO)
*   **Frontend:**
    *   HTML5
    *   CSS3 (basic styling)
    *   JavaScript (Socket.IO client, DOM manipulation)
*   **Security Tools (Development/PoC):**
    *   OpenSSL (for generating self-signed SSL certificates)
*   **Database (Conceptual - In-Memory for PoC):**
    *   User data, room data, messages, and states are stored in Python dictionaries and lists for this prototype. A production version would use a robust database system (e.g., PostgreSQL, MongoDB).

## 4. Project Structure

SecureChatApp/
├── templates/
│ ├── index.html # Main chat interface
│ └── login.html # User login page
├── app.py # Main Flask application logic, SocketIO handlers, security features
├── server.crt # SSL Public Certificate (self-signed, generated by user)
├── server.key # SSL Private Key (self-signed, generated by user)
├── server.csr # Certificate Signing Request (intermediate, generated by user)
├── venv/ # Python virtual environment (recommended, not committed)
└── README.md # This file



## 5. Setup and Running the Project

### Prerequisites:

*   Python 3.8 or higher
*   `pip` (Python package installer)
*   OpenSSL command-line tool (usually pre-installed on Linux/macOS; may need to be installed on Windows)

### Installation & Configuration:

1.  **Clone the repository (or download the source code):**
    ```bash
    git clone https://github.com/your-username/SecureSchoolConnect.git 
    # Or your actual repository URL
    cd SecureSchoolConnect 
    # (Or your project directory name, e.g., cd SecureChatApp)
    ```

2.  **Create and activate a Python virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows:
    # venv\Scripts\activate
    # On macOS/Linux:
    # source venv/bin/activate
    ```

3.  **Install Python dependencies:**
    ```bash
    pip install Flask Flask-SocketIO Flask-Talisman cryptography eventlet
    ```

4.  **Generate Self-Signed SSL Certificates:**
    If `server.crt` and `server.key` are not provided, you need to generate them. Run these commands in the project's root directory (e.g., `SecureChatApp/`):
    ```bash
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr
    # During the .csr generation, when prompted for "Common Name (e.g. server FQDN or YOUR name)", 
    # enter: localhost
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
    ```
    This will create `server.key` and `server.crt` which are necessary for HTTPS.

### Running the Application:

1.  **Start the Flask server:**
    From the project's root directory (e.g., `SecureChatApp/`), run:
    ```bash
    python app.py
    ```
    You should see output indicating the server is running on `https://localhost:5000` (or `https://0.0.0.0:5000`).

2.  **Access the application:**
    Open your web browser and navigate to:
    `https://localhost:5000`

    *   **IMPORTANT BROWSER WARNING:** Because a self-signed certificate is used, your browser will display a security warning ("Your connection is not private," etc.). This is expected. You need to:
        *   Click "Advanced" (or similar wording).
        *   Choose to "Proceed to localhost (unsafe)" or "Accept the Risk and Continue."

## 6. Demonstration & Usage

1.  **Login:** You will be directed to the login page. Use the demo credentials provided on the login page or in the server console output:
    *   `alice / password_student` (Role: student)
    *   `bob / password_teacher` (Role: teacher)
    *   `charlie / password_student2` (Role: student)
    *   `admin / password_admin` (Role: administrator)
2.  **Chat Interface:**
    *   Select a room from the sidebar.
    *   Send and receive messages in real-time.
    *   Observe different UI elements and capabilities based on your role (e.g., "Create Room" button for teachers/admins, mute/delete buttons).
3.  **Test RBAC:**
    *   Log in as a `student` and try to create a room (should not be possible).
    *   Log in as a `teacher`, create a room. Mute a student in the room. Delete a message.
    *   Log in as `admin` and view the "Connected Users" panel.
4.  **Observe Security Features:**
    *   Note the `https://` in the browser address bar.
    *   Check the server console for `AUDIT_LOG` entries corresponding to your actions.
    *   Try to fail login multiple times to see rate-limiting log messages.

## 7. Screenshots (Placeholder)

*(Here, you would embed screenshots after taking them. Suggestions:)*

1.  **Login Page:** `[Screenshot of login.html]`
2.  **Student Chat View:** Showing basic chat interface. `[Screenshot of student view in index.html]`
3.  **Teacher Chat View:** Showing "Create Room" and "Mute" buttons on a student's message. `[Screenshot of teacher view with moderation options]`
4.  **Admin Panel:** Showing the list of connected users. `[Screenshot of admin view with user list]`
5.  **(Optional) Server Console:** Showing example `AUDIT_LOG` lines. `[Screenshot of server console]`

## 8. Future Enhancements

*   **Production-Grade Database:** Replace in-memory stores with a persistent database (e.g., PostgreSQL).
*   **Robust Password Security:** Implement password hashing (bcrypt/Argon2) and complexity requirements.
*   **Multi-Factor Authentication (MFA):** For teacher and administrator accounts.
*   **Key Management Service (KMS):** For secure management of data-at-rest encryption keys.
*   **CA-Issued SSL Certificates:** Replace self-signed certs for trusted HTTPS.
*   **Enhanced Moderation Tools:** User blocking, reporting features.
*   **Direct Messaging:** Private one-to-one chats.
*   **File Sharing:** Securely upload and share files.
*   **Scalability & Deployment:** Containerization (Docker), orchestration (Kubernetes), load balancing for production deployment.
*   **Full DoS/DDoS Protection:** Web Application Firewall (WAF) and other infrastructure hardening.

## 9. Author

*   [Group 40]
*   [Link to your GitHub profile or project page if different]

## 10. License

This project is licensed under the MIT License.
