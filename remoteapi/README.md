# How to start remote server #

- This server is serving as a backend for pycrashext commands running in 'crash' utility
- It can be running as a stand alone or as a docker image if you don't want to touch the running system

## Currently provided services ##

- source code browsing
- running insights rules with the data provided from the 'crash' extensions

## Setup ##

### Configure source directory ###

- Source directory should be specified in RHEL_SOURCE_DIR shell environment variable

```
$ export RHEL_SOURCE_DIR="/Users/sungju/source"
```

- Source directory should have another subdirectories for each kernel types and each should be git repo.

```
fedora/
rhel5/
rhel6/
rhel7/
ubuntu/
upstream/
```

### Configure 'insights' rules ###

- Current repo only has 'insights-core' which is the core for insights engine
- To use additional rules, you need to specify it via 'INSIGHTS_RULES' shell environment variable.

```
$ export INSIGHTS_RULES="/home/sungju/support-rules:/home/sungju/new-rules"
```

## Launching the server ##

- The default port for the server is '5000', but you can change it by specifying the port number in 'PYCRASHEXT_PORT' shell environment variable.

```
$ export PYCRASHEXT_PORT=5000
```

- Starting as a docker server or standalone

```
$ cd remotepai

$ ./start_docker.sh
or
$ ./run_standalone.sh
```
