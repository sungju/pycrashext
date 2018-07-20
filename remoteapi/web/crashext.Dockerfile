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
RUN apt-get install -y python-pip python-dev build-essential git
COPY . /app
COPY ./plugins /app/plugins
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]
