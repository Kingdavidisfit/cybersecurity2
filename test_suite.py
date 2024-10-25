import pytest
import json
import base64
from app import app, get_key_from_db
import jwt
from datetime import datetime, timezone

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

# Test for generating a valid JWT token
def test_valid_auth_token(client):
    response = client.post('/auth')
    assert response.status_code == 200

    data = response.get_json()
    assert 'token' in data

    # Decode the JWT token
    key_data = get_key_from_db(expired=False)
    assert key_data is not None, "No valid key found in DB"
    
    _, key = key_data
    key = base64.urlsafe_b64decode(key).decode('utf-8')
    decoded_token = jwt.decode(data['token'], key, algorithms=['HS256'])

    assert decoded_token['exp'] > datetime.now(timezone.utc).timestamp()

# Test for generating an expired JWT token
def test_expired_auth_token(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200

    data = response.get_json()
    assert 'token' in data

    # Decode the JWT token
    key_data = get_key_from_db(expired=True)
    assert key_data is not None, "No expired key found in DB"
    
    _, key = key_data
    key = base64.urlsafe_b64decode(key).decode('utf-8')

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(data['token'], key, algorithms=['HS256'])

# Test that JWKS endpoint returns valid keys
def test_jwks_endpoint(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200

    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0

    for key in data['keys']:
        assert key['kty'] == 'oct'
        assert key['alg'] == 'HS256'
        assert 'kid' in key
        assert 'k' in key

# Test for handling no keys found case
def test_auth_no_keys_found(client, monkeypatch):
    def mock_get_key_from_db(expired=False):
        return None
    monkeypatch.setattr('app.get_key_from_db', mock_get_key_from_db)

    response = client.post('/auth')
    assert response.status_code == 404

    data = response.get_json()
    assert data['error'] == "No key found"

# Test for ensuring valid keys aren't expired
def test_key_expiry_handling(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200

    data = response.get_json()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    for key in data['keys']:
        key_decoded = base64.urlsafe_b64decode(key['k']).decode('utf-8')
        
        try:
            key_exp = int(jwt.decode(key_decoded, key_decoded, algorithms=['HS256'])['exp'])
        except jwt.DecodeError:
            pytest.fail("JWT key decoding failed")

        assert key_exp > current_time
