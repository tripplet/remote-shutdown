#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 2018-12-28
@author: Tobias Tangemann

Component for shuting down windows pc
"""
import logging

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant.const import (CONF_ACCESS_TOKEN, CONF_HOST, CONF_PORT,
                                 CONF_TIMEOUT)

_LOGGER = logging.getLogger(__name__)

DOMAIN = 'remote_shutdown'

CONF_FORCE = 'force'

REMOTE_SHUTDOWN_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_ACCESS_TOKEN): cv.string,
    vol.Optional(CONF_FORCE, default=True): cv.boolean,
    vol.Optional(CONF_PORT, default=10102): cv.port
})


def setup(hass, config):
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

    def send(call):
        """Send the shutdown command"""
        host = call.data.get(CONF_HOST)
        port = call.data.get(CONF_PORT)
        secret = call.data.get(CONF_ACCESS_TOKEN)
        force = call.data.get(CONF_FORCE)

        _LOGGER.info('Trying shutdown of %s', host)
        result, error = shutdown(host, port, secret, force, 10.0)

        if result:
            _LOGGER.info('Shutdown successful')
        else:
            _LOGGER.error('Error during send shutdown: %s', error)

    hass.services.register(DOMAIN, 'send', send, schema=REMOTE_SHUTDOWN_SCHEMA)
    return True
