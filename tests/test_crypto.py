from sud.crypto import generate_key, encrypt_trip_data, decrypt_trip_data


def test_encrypt_decrypt_roundtrip():
    key = generate_key()
    payload = {"origin": "A", "destination": "B", "price": 12.5}
    token = encrypt_trip_data(key, payload)
    recovered = decrypt_trip_data(key, token)
    assert recovered == payload
