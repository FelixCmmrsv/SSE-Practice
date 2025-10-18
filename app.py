from flask import Flask, request, jsonify, session
import sqlite3
import bcrypt
import secrets
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            full_name TEXT
        )
    ''')
    hashed_password = bcrypt.hashpw('SecurePass123!'.encode(), bcrypt.gensalt())
    try:
        c.execute(
            "INSERT INTO users (username, password, email, full_name) VALUES (?, ?, ?, ?)",
            ('secure_user', hashed_password.decode(), 'secure@example.com', 'Secure User')
        )
    except sqlite3.IntegrityError:
        pass
    try:
        c.execute(
            "INSERT INTO users (username, password, email, full_name) VALUES (?, ?, ?, ?)",
            ('admin', 'admin123', 'admin@example.com', 'Admin User')
        )
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/insecure_login', methods=['POST'])
def insecure_login():
    try:
        data = request.get_json() or request.form
        user = data.get('username', '')
        pwd = data.get('password', '')
        db = get_db()
        query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
        result = db.execute(query).fetchone()
        db.close()
        if result:
            session['user_id'] = result['id']
            session['username'] = result['username']
            return jsonify({
                'status': 'success',
                'message': 'Welcome!',
                'user': dict(result)
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid username or password'
            }), 401
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}'
        }), 500

@app.route('/insecure_profile/<username>', methods=['GET'])
def insecure_profile(username):
    try:
        db = get_db()
        query = f"SELECT * FROM users WHERE username='{username}'"
        print(f"[INSECURE] Executing query: {query}")
        
        result = db.execute(query).fetchone()
        db.close()
        
        if result:
            return jsonify({
                'status': 'success',
                'user': dict(result)
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500
    
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({
                'status': 'error',
                'message': 'Authentication required'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/secure_register', methods=['POST'])
def secure_register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request'
            }), 400
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        full_name = data.get('full_name', '').strip()
        if not username or len(username) < 3:
            return jsonify({
                'status': 'error',
                'message': 'Username must be at least 3 characters'
            }), 400
        if not password or len(password) < 8:
            return jsonify({
                'status': 'error',
                'message': 'Password must be at least 8 characters'
            }), 400
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, email, full_name) VALUES (?, ?, ?, ?)",
                (username, hashed_password.decode(), email, full_name)
            )
            db.commit()
            return jsonify({
                'status': 'success',
                'message': 'User registered successfully'
            }), 201
        except sqlite3.IntegrityError:
            return jsonify({
                'status': 'error',
                'message': 'Registration failed'
            }), 400
        finally:
            db.close()
    except Exception as e:
        print(f"[ERROR] Registration error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred during registration'
        }), 500

@app.route('/secure_login', methods=['POST'])
def secure_login():
    try:
        data = request.get_json() or request.form
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request'
            }), 400
        username = data.get('username', '').strip()
        password = data.get('password', '')
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
        db = get_db()
        cur = db.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        )
        user = cur.fetchone()
        db.close()
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({
                'status': 'success',
                'message': 'Login successful',
                'username': user['username']
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
    except Exception as e:
        # Log error internally but return generic message
        print(f"[ERROR] Login error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred during login'
        }), 500

@app.route('/secure_profile', methods=['GET'])
@require_auth
def secure_profile():
    try:
        user_id = session.get('user_id')
        db = get_db()
        cur = db.execute(
            "SELECT id, username, email, full_name FROM users WHERE id = ?",
            (user_id,)
        )
        user = cur.fetchone()
        db.close()
        if user:
            return jsonify({
                'status': 'success',
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'full_name': user['full_name']
                }
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
    except Exception as e:
        print(f"[ERROR] Profile error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred'
        }), 500

@app.route('/secure_profile/update', methods=['PUT'])
@require_auth
def secure_update_profile():
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid request'
            }), 400
        allowed_fields = {'email', 'full_name'}
        update_fields = {k: v for k, v in data.items() if k in allowed_fields}
        if not update_fields:
            return jsonify({
                'status': 'error',
                'message': 'No valid fields to update'
            }), 400
        set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
        values = list(update_fields.values()) + [user_id]
        db = get_db()
        db.execute(
            f"UPDATE users SET {set_clause} WHERE id = ?",
            values
        )
        db.commit()
        db.close()
        return jsonify({
            'status': 'success',
            'message': 'Profile updated successfully'
        }), 200
    except Exception as e:
        print(f"[ERROR] Update error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred'
        }), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({
        'status': 'success',
        'message': 'Logged out successfully'
    }), 200

@app.route('/')
def index():
    return jsonify({
        'message': 'DevSecOps Lab - Secure Coding Demo',
        'endpoints': {
            'insecure': {
                'login': 'POST /insecure_login',
                'profile': 'GET /insecure_profile/<username>'
            },
            'secure': {
                'register': 'POST /secure_register',
                'login': 'POST /secure_login',
                'profile': 'GET /secure_profile',
                'update': 'PUT /secure_profile/update',
                'logout': 'POST /logout'
            }
        },
        'warning': 'The /insecure_* endpoints are intentionally vulnerable for educational purposes only!'
    })

if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("DevSecOps Lab - Secure Coding Implementation")
    print("=" * 60)
    print("\n⚠️  WARNING: This application contains intentionally insecure code")
    print("for educational purposes. DO NOT use in production!\n")
    print("Insecure endpoints (for demonstration):")
    print("  - POST /insecure_login")
    print("  - GET /insecure_profile/<username>")
    print("\nSecure endpoints (best practices):")
    print("  - POST /secure_register")
    print("  - POST /secure_login")
    print("  - GET /secure_profile")
    print("  - PUT /secure_profile/update")
    print("  - POST /logout")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)
