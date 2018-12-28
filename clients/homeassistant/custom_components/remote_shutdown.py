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
    vol.Optional(CONF_TIMEOUT, default=3.0): cv.socket_timeout,
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
        hashed_message = hmac.new(key.encode('ascii'), message, hashlib.sha256)
        return f'{cmd}.{hashed_message.hexdigest()}'

    def shutdown(host, port, secret, force, socket_timeout):
        """Send shutdown command to the specified host"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(socket_timeout)
            try:
                # connect, request the challenge and send the signed response
                s.connect((host, port))
                s.send(b'request_challange\n')
                challenge = s.recv(2048).decode('ascii')
                response = authenticated_response(challenge, secret, force)
                s.send((response + '\n').encode('ascii'))
                result = s.recv(2048).decode('ascii')
                if result == '1':
                    return True, None
                return False, result
            except Exception as exp:
                return False, str(exp)
            finally:
                s.close()

    def send(call):
        """Send the shutdown command"""
        host = call.data.get(CONF_HOST)
        port = call.data.get(CONF_PORT)
        secret = call.data.get(CONF_ACCESS_TOKEN)
        force = call.data.get(CONF_FORCE)
        socket_timeout = call.data.get(CONF_TIMEOUT)

        _LOGGER.info('Trying shutdown of %s', host)
        result, error = shutdown(host, port, secret, force, socket_timeout)

        if result:
            _LOGGER.info('Shutdown successful')
        else:
            _LOGGER.error('Error during send shutdown: %s', error)

    hass.services.register(DOMAIN, 'send', send, schema=REMOTE_SHUTDOWN_SCHEMA)
    return True
