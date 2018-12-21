"""
Script for shuting down windows pc
"""
import socket
import hashlib
import hmac

def authenticated_response(challenge, key, force):
    """Calculate a response using the scret and the given challenge"""
    if len(challenge) < 32:
        raise Exception("Invalid challenge")
    if force:
        cmd = 'admin_shutdown'
    else:
        cmd = 'shutdown'
    message = f'{cmd}.{challenge}'.encode('ascii')
    hash = hmac.new(key.encode('ascii'), message, hashlib.sha256)
    return f'{cmd}.{challenge}#{hash.hexdigest()}'

def shutdown(host, port, secret, force, socket_timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(socket_timeout)

    try:
        # connect, request the challenge and send the signed response
        s.connect((host, port))
        s.send(b'request_shutdown\n')
        challenge = s.recv(2048).decode('ascii')
        response = authenticated_response(challenge, secret, force)
        s.send((response + '\n').encode('ascii'))
        result = s.recv(2048).decode('ascii')
        if result == '1':
            return True, None
        else:
            return False, result
    except Exception as exp:
            return False, str(exp)
    finally:
        s.close()

result, error = shutdown('localhost', 10102, 'test', True, 30)

if result:
    print("Shutdown successful")
else:
    print(f'Error: {error}')