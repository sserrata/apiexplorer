FROM python:3.6-alpine
MAINTAINER Steven Serrata <sserrata@paloaltonetworks.com>

ENV PYTHONUNBUFFERED 1

apk add --upgrade alpine-sdk
RUN mkdir -p /opt/apiexplorer
RUN mkdir -p /var/log/gunicorn
ADD . /opt/apiexplorer/
RUN pip install pip --upgrade
RUN pip install -r /opt/apiexplorer/requirements.txt
WORKDIR /opt/apiexplorer

# Start app in unix socket mode (add "-d" to listen on TCP)
# CMD python run.py

