# -*- coding: utf-8 -*-
# Copyright (C) Bouvet ASA - All Rights Reserved.

import flask
from flask import Flask, request, Response
from werkzeug.exceptions import BadRequest, Forbidden, NotFound
import logging.handlers
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import cherrypy
import threading
import time
import json
import uuid
import copy

app = Flask(__name__)

logger = logging.getLogger('counting-semaphore')

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

semaphore_writers_lock = threading.Lock()
session_writers_lock = threading.Lock()
readers_lock = threading.Lock()

semaphores = {}
sessions = {}


@app.route('/', methods=['GET'])
def root():
    return Response(status=200, response="I am Groot!")


@app.route('/dump-all', methods=['GET'])
def dump_all():
    with session_writers_lock:
        _sessions = copy.deepcopy(sessions)

    with semaphore_writers_lock:
        _semaphores = copy.deepcopy(semaphores)

    return Response(json.dumps({"semaphores": _semaphores, "sessions": _sessions}), mimetype='application/json')


@app.route('/dump-sessions', methods=['GET'])
def dump_sessions():
    with session_writers_lock:
        _sessions = copy.deepcopy(sessions)

    return Response(json.dumps(_sessions), mimetype='application/json')


@app.route('/dump-semaphores', methods=['GET'])
def dump_semaphores():
    with semaphore_writers_lock:
        _semaphores = copy.deepcopy(semaphores)

    return Response(json.dumps(_semaphores), mimetype='application/json')


@app.route('/get-semaphore', methods=['POST'])
def get_semaphore():
    global semaphores
    global sessions

    semaphore_id = request.args.get('semaphore')
    holder_payload = request.args.get('holder_payload')

    if isinstance(holder_payload, str):
        try:
            holder_payload = json.loads(holder_payload)
        except:
            holder_payload = "no payload"

    if not semaphore_id:
        raise BadRequest("Parameter 'semaphore_id' required")

    try:
        max_holders = int(request.args.get('max_holders', 10))
    except ValueError:
        logger.warning("Error in max_holders parameter: %s" % request.args.get('max_holders'))
        max_holders = 10

    try:
        ttl = int(request.args.get('ttl', 60))
    except ValueError:
        logger.warning("Error in ttl parameter: %s" % request.args.get('ttl'))
        ttl = 60

    with semaphore_writers_lock:
        if not semaphore_id in semaphores:
            semaphores[semaphore_id] = {
                "holders": {}
            }

        semaphore = semaphores[semaphore_id]
        semaphore["max_holders"] = max_holders

        if len(semaphore["holders"]) >= semaphore["max_holders"]:
            logger.debug("Maximum number of semaphore holders for '%s' reached, try again later" % semaphore_id)
            raise Forbidden("Maximum number of semaphore holders for '%s' reached, try again later" % semaphore_id)

        session_id = str(uuid.uuid4())
        created = time.time()

        session_info = {
            "payload": holder_payload,
            "created": created,
            "updated": created,
            "ttl": ttl,
            "semaphore": semaphore_id
        }

        semaphore["holders"][session_id] = session_info

    with session_writers_lock:
        sessions[session_id] = session_info

    logger.debug("Acquired semaphore id '%s' - holders: %s of max %s" % (semaphore_id, len(semaphore["holders"]),
                                                                         semaphore["max_holders"]))

    return Response(json.dumps({"session": session_id}), mimetype='application/json')


@app.route('/release-semaphore', methods=['DELETE'])
def release_semaphore():
    global sessions
    global semaphores

    semaphore_id = request.args.get('semaphore')

    if not semaphore_id:
        raise BadRequest("Parameter 'semaphore_id' required")

    with semaphore_writers_lock:
        if semaphore_id not in semaphores:
            raise NotFound("Semaphore with id '%s' not found" % semaphore_id)

        semaphore = semaphores[semaphore_id]
        semaphores.pop(semaphore_id)

    with session_writers_lock:
        for session_id in semaphore["holders"]:
            if session_id in sessions:
                sessions.pop(session_id)

    logger.debug("Released semaphore '%s'" % semaphore_id)

    return Response("Semaphore '%s' released" % semaphore_id, mimetype='text/plain')


@app.route('/release-session', methods=['DELETE'])
def release_session():
    global session
    global semaphores

    session_id = request.args.get('session')

    if not session_id:
        raise BadRequest("Parameter 'session' required")

    with session_writers_lock:
        if session_id not in sessions:
            raise NotFound("No active session found for session id '%s' - perhaps it has timed out?" % session_id)

        session = sessions[session_id]
        sessions.pop(session_id)

        logger.debug("Released session '%s' (%s)" % (session_id, json.dumps(session)))

    with semaphore_writers_lock:
        semaphore_id = session["semaphore"]
        semaphore = semaphores.get(semaphore_id)
        if semaphore:
            if session_id in semaphore["holders"]:
                semaphore["holders"].pop(session_id)

    return Response("Session '%s' released" % session_id, mimetype='text/plain')


@app.route('/renew-session', methods=['POST'])
def renew_session():
    global sessions

    session_id = request.args.get('session')

    if not session_id:
        raise BadRequest("Parameter 'session' required")

    with session_writers_lock:
        if session_id not in sessions:
            raise NotFound("No active session found for session id '%s' - perhaps it has timed out?" % session_id)

        session = sessions[session_id]
        session["updated"] = time.time()

        logger.debug("Renewed session '%s' (%s)" % (session_id, json.dumps(session)))

        return Response(json.dumps(session), mimetype='application/json')


def run_session_pruning():
    global sessions
    global semaphores

    while True:
        try:
            time.sleep(3)
            now = time.time()

            logger.info("Pruning sessions..")

            with session_writers_lock:
                for session_id, session in list(sessions.items()):
                    if now > session["updated"] + session["ttl"]:
                        logger.info("Pruning session '%s' - it has timed out.." % session)

                        # Prune the session, it has timed out
                        with semaphore_writers_lock:
                            semaphore_id = session["semaphore"]
                            semaphore = semaphores[semaphore_id]
                            if session_id in semaphore["holders"]:
                                semaphore["holders"].pop(session_id)

                        sessions.pop(session_id)

                logger.info("Number of active sessions after pruning: %s" % len(sessions))

        except BaseException as e:
            # log exception but keep executing
            logger.exception("Session pruner thread crashed")


@app.route('/set-log-level', methods=['PUT'])
def set_log_level():
    loglevel = request.args.get('loglevel')

    if loglevel and isinstance(loglevel, str):
        loglevel = loglevel.upper()

        if loglevel == "DEBUG":
            logger.info("Setting loglevel to DEBUG")
            logger.setLevel(logging.DEBUG)
        elif loglevel == "INFO":
            logger.info("Setting loglevel to INFO")
            logger.setLevel(logging.INFO)
        elif loglevel == "WARN" or loglevel == "WARNING":
            logger.info("Setting loglevel to WARN")
            logger.setLevel(logging.WARNING)
        elif loglevel == "ERROR" or loglevel == "ERR":
            logger.info("Setting loglevel to ERROR")
            logger.setLevel(logging.ERROR)


if __name__ == '__main__':
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(stdout_handler)

    logger.propagate = False
    logger.setLevel(logging.DEBUG)

    pruner_thread = threading.Thread(target=run_session_pruning)
    pruner_thread.start()

    cherrypy.tree.graft(app, '/')

    # Set the configuration of the web server
    cherrypy.config.update({
        'environment': 'production',
        'engine.autoreload_on': False,
        'log.screen': True,
        'server.socket_port': 5115,
        'server.socket_host': '0.0.0.0',
        'server.thread_pool': 10
    })

    # Start the CherryPy WSGI web server
    cherrypy.engine.start()
    cherrypy.engine.block()
