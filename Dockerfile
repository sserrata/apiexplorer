FROM python:3
MAINTAINER Steven Serrata <sserrata@paloaltonetworks.com>

ENV PYTHONUNBUFFERED 1

RUN mkdir -p /opt/apiexplorer
RUN mkdir -p /var/log/gunicorn
ADD . /opt/apiexplorer/
RUN pip3 install pip --upgrade
RUN pip3 install -r /opt/apiexplorer/requirements.txt
WORKDIR /opt/apiexplorer

# Start app in unix socket mode (add "-d" to listen on TCP)
# CMD python3 run.py

