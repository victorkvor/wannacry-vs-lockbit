from Crypto.Cipher import AES

# Decrypted AES key
key = bytes.fromhex("bee19b98d2e5b12211ce211eecb13de6")

# Empty IV (16 null bytes)
iv = b"\x00" * 16

# Initialize AES cipher in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

# Read encrypted data
with open("encrypted_payload.bin", "rb") as f:
    enc_payload = f.read()

# Decrypt the payload
dec_payload = cipher.decrypt(enc_payload)

# Save decrypted content
with open("mysterious_executable.bin", "wb") as f:
    f.write(dec_payload)

print("Decryption complete: mysterious_executable.bin created.")