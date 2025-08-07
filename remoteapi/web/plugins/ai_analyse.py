"""
Written by Daniel Sungju Kwon

It gets some help from specified AI engine for the remote data
"""
from flask import Flask, request, jsonify
import requests
import threading
import time
from datetime import datetime, timedelta
import re
import os
import base64
import subprocess


OLLAMA_API_URL = "http://localhost:11434/api/chat"
PODMAN_API_URL = "http://localhost:65445/v1/chat/completions"
MODEL_NAME = "llama3.2"
INACTIVITY_TIMEOUT = timedelta(days=1)
MAX_HISTORY = 10


def add_plugin_rule(app):
    app.add_url_rule('/api/ai', 'ai', ai_analyse, methods=['POST'])


# Shared state
lock = threading.Lock()
active_sessions = {}

def get_normalized_request_data():
    if request.is_json:
        # JSON input
        data = request.get_json()
    elif request.form:
        # Form input (e.g. from application/x-www-form-urlencoded or multipart/form-data)
        data = request.form.to_dict()
    else:
        data = {}

    return data


class SessionThread:
    def __init__(self, session_id):
        self.session_id = session_id
        self.message_history = []
        self.last_activity = datetime.now()
        self.lock = threading.Lock()

    def send_message(self, prompt, engine, model, reset_history=False):
        with self.lock:
            self.last_activity = datetime.now()
            if reset_history or self.message_history.isEmpty():
                self.message_history = [{"role": "system",\
                      "content": "Please provide results in Markdown format"}]

            self.message_history.append({"role": "user", "content": prompt})
            self.message_history = self.message_history[-MAX_HISTORY * 2:]

            if engine == "ollama":
                engine_url = OLLAMA_API_URL
            elif engine == "podman":
                engine_url = PODMAN_API_URL
            else:
                engine_url = OLLAMA_API_URL

            try:
                response = requests.post(
                    engine_url,
                    json={
                        "model": model,
                        "messages": self.message_history,
                        "stream": False
                    },
                    timeout=120
                )
                json_data = response.json()
                if "choices" in json_data:
                    reply = json_data["choices"][0]["message"]["content"]
                else:
                    reply = json_data["message"]["content"]

            except Exception as e:
                reply = f"Error: {e}"

            self.message_history.append({"role": "assistant", "content": reply})
            return reply

    def is_expired(self):
        return datetime.now() - self.last_activity > INACTIVITY_TIMEOUT


def get_or_create_session(session_id):
    with lock:
        if session_id not in active_sessions:
            active_sessions[session_id] = SessionThread(session_id)
        return active_sessions[session_id]


# Background cleanup thread
def cleanup_loop():
    while True:
        time.sleep(3600)  # Check every hour
        with lock:
            expired = [
                sid for sid, sess in active_sessions.items()
                if sess.is_expired()
            ]
            for sid in expired:
                del active_sessions[sid]
                print(f"[CLEANUP] Session '{sid}' expired and removed.")


def ai_analyse():
    data = get_normalized_request_data()
    session_id = data.get("session_id")
    prompt = data.get("query")

    engine = data.get("engine")
    if not engine:
        engine = "ollama"

    model = data.get("model")
    if not model:
        model = MODEL_NAME

    reset = data.get("reset")
    if reset != "":
        reset_history = True
    else:
        reset_history = False

    try:
        prompt = base64.b64decode(prompt).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decode query_str: {e}")

    if not session_id or not prompt:
        return jsonify({"error": "Missing session_id or prompt"}), 400

    session = get_or_create_session(session_id)
    reply = session.send_message(prompt, engine, model, reset_history)
    return jsonify({"response": reply})


if __name__ == "__main__":
    threading.Thread(target=cleanup_loop, daemon=True).start()
    app.run(port=5000, debug=True)
