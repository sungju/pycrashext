"""
Help text for 'help <command>' and 'man <command>' in crash, for regext.py.

crash shows a registered command's help as NAME (<command> - <desc>),
SYNOPSIS (<command> <options>) and DESCRIPTION (<help>), from the strings
given when it was registered. regext.py fills them from what the command's
own '-h' prints, so the three agree: the usage line becomes the synopsis
and the rest the description, after the one-line summary from config.json.

Running a command's '-h' takes a moment, so the text is cached per script
file, keyed on its modification time and size; a changed script is run
again on the next crash start.

This module deliberately imports nothing from pykdump, so its checks run
with the system python3 (helptext_test.py).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import json
import os
import re
import tempfile

CACHE_VERSION = 1


def cache_file(environ):
    """Where the help cache lives: $XDG_CACHE_HOME or ~/.cache, then pycrashext."""
    base = environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "pycrashext", "help.json")


def find_script(name, dirs):
    """The first <name>.py in `dirs`, the way crash looks a command up along
    PYKDUMPPATH; None when there is none."""
    for d in dirs:
        path = os.path.join(d, name + ".py")
        if os.path.isfile(path):
            return os.path.realpath(path)
    return None


def split_help(text):
    """
    Split '-h' output into (usage, body). usage is the 'Usage:' paragraph
    without that word, on one line ('edis.py [options]'); body is the rest.
    usage is None when the output has no usage line; any lines before it
    (an error message, say) are dropped.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^\s*usage:\s*(.*)$', line, re.IGNORECASE)
        if m is None:
            continue
        usage = [m.group(1).strip()]
        j = i + 1
        while j < len(lines) and lines[j].strip() != "" and \
              lines[j].startswith((" ", "\t")):
            usage.append(lines[j].strip())
            j = j + 1
        body = "\n".join(lines[j:]).strip("\n")
        return " ".join(u for u in usage if u), body
    return None, text.strip("\n")


def synopsis(usage):
    """The usage without the program name crash already prints:
    'edis.py [options]' -> '[options]'."""
    parts = usage.split(None, 1)
    return parts[1] if len(parts) > 1 else ""


def summary(help_str):
    """The first paragraph of a config.json 'help' string."""
    return help_str.strip().split("\n\n")[0].strip()


def crash_help(cmd_info, text):
    """
    (options, help) to register for a command whose '-h' printed `text`.
    Falls back to config.json's own strings when the output has no usage
    line, which means the command did not print a help message.
    """
    usage, body = split_help(text or "")
    if usage is None:
        return cmd_info["options"], cmd_info["help"]
    first = summary(cmd_info["help"])
    help_str = first + "\n\n" + body if (first and body) else (first or body)
    return synopsis(usage), help_str


def load_cache(path):
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("version") == CACHE_VERSION and \
           isinstance(data.get("scripts"), dict):
            return data["scripts"]
    except (OSError, ValueError):
        pass
    return {}


def save_cache(path, scripts):
    """Write the cache atomically; a cache that can't be written is skipped."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".help-")
        with os.fdopen(fd, "w") as f:
            json.dump({"version": CACHE_VERSION, "scripts": scripts}, f)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def cached_help(cache, script, compute, deps=()):
    """
    The '-h' output of `script`, from `cache` when neither the file nor any
    of `deps` (modules that add to every command's '-h', like optexamples.py)
    has changed since, otherwise from compute(script), which is then stored
    in `cache`. Returns (text, changed); text is None when compute() gave
    nothing.
    """
    try:
        st = os.stat(script)
    except OSError:
        return None, False
    stamp = [st.st_mtime_ns, st.st_size]
    for dep in deps:
        try:
            st = os.stat(dep)
            stamp += [st.st_mtime_ns, st.st_size]
        except OSError:
            stamp += [None, None]
    entry = cache.get(script)
    if isinstance(entry, dict) and entry.get("stamp") == stamp:
        return entry.get("text"), False
    text = compute(script)
    if text is None:
        return None, False
    cache[script] = {"stamp": stamp, "text": text}
    return text, True
