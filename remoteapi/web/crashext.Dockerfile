#
# crash extension server docker image
#
# Written by Daniel Sungju Kwon
# dkwon@redhat.com
#
FROM ubuntu:latest
LABEL maintainer dkwon@redhat.com
MAINTAINER dkwon@redhat.com

RUN apt-get update -y
RUN apt-get install -y python3 python3-pip python3-dev build-essential git-core python3-venv python-six
COPY . /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
