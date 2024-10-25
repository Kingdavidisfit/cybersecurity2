import base64
from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
import sqlite3

db_file = 'totally_not_my_privateKeys.db'

# Initialize the database and insert keys
def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )''')
    
    # Inserting two keys: one valid, one expired
    valid_key = '3ba010226cd84939b9eed91aa6bd9519'
    expired_key = '3ba010226cd84939b9eed91aa6bd9519'  # Same key for demonstration
    
    # Convert keys to base64 for JWKS
    valid_key_encoded = base64.urlsafe_b64encode(valid_key.encode('utf-8')).decode('utf-8')
    expired_key_encoded = base64.urlsafe_b64encode(expired_key.encode('utf-8')).decode('utf-8')
    
    # Expiration times
    time_valid = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())  # valid for 1 hour
    time_expired = int((datetime.now(timezone.utc) - timedelta(seconds=10)).timestamp())  # expired 10 seconds ago
    
    # Insert into database
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (valid_key_encoded, time_valid))
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_key_encoded, time_expired))
    conn.commit()
    conn.close()

# Retrieve key from DB based on expiration status
def get_key_from_db(expired=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ? LIMIT 1', (current_time,))
    
    row = cursor.fetchone()
    conn.close()
    return row

# Initialize Flask app
app = Flask(__name__)
init_db()

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired') is not None

    # Fetch key from DB
    key_data = get_key_from_db(expired=expired)
    if not key_data:
        return jsonify({"error": "No key found"}), 404

    kid, key = key_data
    key = base64.urlsafe_b64decode(key).decode('utf-8')  # Decode from base64

    # Create JWT payload
    body = {
        'Fullname': "username",
        'Password': "password",
        'iat': datetime.now(timezone.utc),
    }

    if expired:
        # Set token to be expired
        body['exp'] = datetime.now(timezone.utc) - timedelta(seconds=10)
    else:
        # Set token to expire in 1 hour
        body['exp'] = datetime.now(timezone.utc) + timedelta(hours=1)

    # Encode JWT
    token = jwt.encode(body, key, algorithm='HS256', headers={'kid': str(kid)})

    return jsonify({"token": token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (current_time,))
    rows = cursor.fetchall()
    conn.close()

    # Create JWKS response
    jwks_data = {"keys": []}
    for row in rows:
        kid, key = row
        jwks_data["keys"].append({
            "kty": "oct",
            "k": key,
            "alg": "HS256",
            "use": "sig",
            "kid": str(kid)
        })

    return jsonify(jwks_data)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)