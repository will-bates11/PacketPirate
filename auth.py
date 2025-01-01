
from functools import wraps
from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token required'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorator
from functools import wraps
from flask import Flask, request, jsonify
import jwt
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

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

@app.route('/api/capture', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
@csrf.exempt
def api_capture():
    data = request.get_json()
    if not validate_input(data):
        return jsonify({'error': 'Invalid input'}), 400
    packets = capture_packets(
        interface=data.get('interface', 'eth0'),
        count=data.get('count', 100),
        filter_str=data.get('filter')
    )
    df = analyze_packets(packets)
    return jsonify(df.to_dict())
