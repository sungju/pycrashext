# remoteapi - backend server for pycrashext #

- This server is the backend for the pycrashext commands that run inside the 'crash' utility.
- Some commands cannot do their work from within PyKdump (limited libraries, no access to the source tree, no AI engine), so they call this server over HTTP instead.
- It can run either as a standalone Flask process or as a docker/compose service, so you don't have to install anything extra on the machine that runs 'crash'.

## Services provided ##

The server loads every plugin under `web/plugins/` at start-up. The currently active endpoints are:

| Endpoint | Method | Used by | Purpose |
|---|---|---|---|
| `/api/disasm` | POST | edis | Source-level disassembly using the kernel source tree |
| `/api/setgit/<asm_str>` | GET | edis | Select the git source repo for disassembly |
| `/api/git` | POST | git | Run `git log` / `git show` in the kernel source repos |
| `/api/ai` | POST | ai | Forward command output to an AI engine (ollama/podman) and return the analysis |
| `/list` | GET | — | List all registered routes |
| `/reload` | GET | — | Reload plugins without restarting |

> NOTE: The `insights` plugin is currently shipped as `web/plugins/insights.py.deprecated` and is **not** loaded by default. Rename it back to `insights.py` if you want to re-enable the `/api/insights` endpoint used by the `insights` crash command.

## Setup ##

### Configure the source directory ###

- The kernel source directory must be provided via the `RHEL_SOURCE_DIR` environment variable.

```
$ export RHEL_SOURCE_DIR="/Users/sungju/source"
```

- That directory should contain one git repository per kernel type, for example:

```
<RHEL_SOURCE_DIR> -+-- fedora/
                   +-- rhel5/
                   +-- rhel6/
                   +-- rhel7/
                   +-- rhel8/
                   +-- rhel9/
                   +-- ubuntu/
                   +-- upstream/
```

- It does not need every repository — only the ones you plan to use.

### Configure 'insights' rules (optional) ###

- Only used when the `insights` plugin is re-enabled (see the note above).
- The repo ships the `insights-core` engine only. Additional rule directories are provided via the `INSIGHTS_RULES` environment variable (colon-separated).

```
$ export INSIGHTS_RULES="/home/sungju/support-rules:/home/sungju/new-rules"
```

- When using docker, rule directories placed under `./insights-rules/` are picked up automatically and mounted into the container.

## Environment variables ##

| Variable | Default | Description |
|---|---|---|
| RHEL_SOURCE_DIR | (required) | Path to the directory holding the kernel source git repositories |
| PYCRASHEXT_PORT | 5000 | Port the server listens on |
| INSIGHTS_RULES | (unset) | Colon-separated list of extra insights rule directories |
| PYCRASHEXT_API_KEY | (unset) | If set, requests must send a matching `X-API-Key` header; otherwise auth is disabled |
| PYCRASHEXT_DEBUG | (unset) | Set to `1`/`true`/`yes` to enable Flask reloader/debug behavior |

## Launching the server ##

Set `RHEL_SOURCE_DIR` (and optionally `PYCRASHEXT_PORT`) first, then start either flavor from the `remoteapi` directory.

```
$ export RHEL_SOURCE_DIR="/Users/sungju/source"
$ export PYCRASHEXT_PORT=5000
$ cd remoteapi
```

### As a docker / compose service ###

Requires docker with the compose plugin (or `docker-compose`).

```
$ ./start_docker.sh            # start the container
$ ./start_docker.sh -b         # rebuild the image first, then start
$ ./start_docker.sh --dry-run  # print the compose commands without running them
$ ./start_docker.sh --check-only   # validate environment only
```

### As a standalone process ###

Requires `python3` and `pip` (a virtualenv is created automatically by `web/entrypoint.sh`).

```
$ ./run_standalone.sh
$ ./run_standalone.sh --dry-run     # print the command without executing
$ ./run_standalone.sh --check-only  # validate environment only
```

Both scripts accept `-h`/`--help` and validate that `RHEL_SOURCE_DIR` exists before starting.

## Pointing crash at the server ##

On the machine that runs 'crash', set `CRASHEXT_SERVER` to this server's address before launching 'crash'. The pycrashext `install.sh` can also configure this for you.

```
$ export CRASHEXT_SERVER=http://myserver:5000
$ crash
```
