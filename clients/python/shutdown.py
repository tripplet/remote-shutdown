#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 2018-12-28
@author: Tobias Tangemann

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
    mac = hmac.new(key.encode('ascii'), message, hashlib.sha256)
    return f'{cmd}.{challenge}.{mac.hexdigest()}'

def shutdown(host, port, secret, force, socket_timeout):
    """Send shutdown command to the specified host"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(socket_timeout)
        try:
            # connect, request the challenge and send the signed response
            conn.connect((host, port))
            conn.send(b'request_challange\n')
            challenge = conn.recv(2048).decode('ascii').strip()
            response = authenticated_response(challenge, secret, force)
            conn.send((response + '\n').encode('ascii'))
            result = conn.recv(2048).decode('ascii').strip()
            if result == '1':
                return True, None
            return False, result
        except Exception as exp:
            return False, str(exp)
        finally:
            conn.close()

def main():
    """Main function"""
    result, error = shutdown('localhost', 10102, 'test', False, 30)

    if result:
        print("Shutdown successful")
    else:
        print(f'Error: {error}')


if __name__ == '__main__':
    main()
