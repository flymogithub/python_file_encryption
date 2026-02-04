from cryptography import fernet

# Generate a key
key = fernet.Fernet.generate_key()

# save key to a file
with open ('/home/developer/.fernet/filekey.key', 'wb') as f:
    f.write(key)
