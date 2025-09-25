import os
import socket
import base64

# SA-013 (Python Exec) - Should receive heightened score in __init__.py
exec("print('hello')")

# SA-014 (Dynamic Import)
__import__('os')

# SA-015 (Env Access)
token = os.environ.get('AWS_SECRET_KEY')

# SA-016 (Socket)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SA-017 (Base64)
payload = base64.b64decode("SGVsbG8=")
