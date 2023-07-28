#
# crash extension server docker image
#
# Written by Sungju Kwon
# sungju.kwon@gmail.com
#
FROM ubuntu:latest
LABEL maintainer sungju.kwon@gmail.com
MAINTAINER sungju.kwon@gmail.com

RUN apt-get update -y && apt-get install -y \
	build-essential \
	git-core \
	python3 \
	python3-dev \
	python3-six \
	python3-pip \
	python3-venv \
	&& rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
