
from functools import wraps
from flask import request, jsonify, session, current_app
import jwt
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import re
import bcrypt
import html

# These will be initialized by the main app
csrf = None
limiter = None

def init_auth(app):
    """Initialize authentication components with the Flask app."""
    global csrf, limiter
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)
    
    csrf = CSRFProtect(app)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per day", "10 per minute"]
    )
    limiter.init_app(app)

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
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            if 'session_id' not in session or session['session_id'] != payload['session_id']:
                raise jwt.InvalidTokenError
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorator

# Route definitions moved to main app
