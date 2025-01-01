
from functools import wraps
from flask import Flask, request, jsonify, session
import jwt
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import re
import bcrypt
import html

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)

csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

def sanitize_input(data):
    """Sanitize input data"""
    if isinstance(data, str):
        return html.escape(data.strip())
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(i) for i in data]
    return data

def validate_input(data):
    """Validate input data"""
    if not isinstance(data, dict):
        return False
    required = ['interface', 'count']
    if not all(k in data for k in required):
        return False
    if not re.match(r'^[a-zA-Z0-9]+$', data['interface']):
        return False
    try:
        count = int(data['count'])
        return 0 < count <= 1000
    except (ValueError, TypeError):
        return False
    return True

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token required'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if 'session_id' not in session or session['session_id'] != payload['session_id']:
                raise jwt.InvalidTokenError
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorator

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = sanitize_input(request.get_json())
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Invalid credentials'}), 400
    
    # Here you would verify against your user database
    # This is a placeholder for demonstration
    if data['username'] == 'admin' and data['password'] == 'secure_password':
        session_id = str(datetime.datetime.now().timestamp())
        session['session_id'] = session_id
        token = jwt.encode({
            'user': data['username'],
            'session_id': session_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/capture', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
@csrf.exempt
def api_capture():
    data = sanitize_input(request.get_json())
    if not validate_input(data):
        return jsonify({'error': 'Invalid input'}), 400
    packets = capture_packets(
        interface=data.get('interface', 'eth0'),
        count=data.get('count', 100),
        filter_str=data.get('filter')
    )
    df = analyze_packets(packets)
    return jsonify(df.to_dict())

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})
