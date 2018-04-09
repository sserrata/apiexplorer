FROM python:3
MAINTAINER Steven Serrata <sserrata@paloaltonetworks.com>

RUN mkdir -p /opt/apiexplorer
ADD . /opt/apiexplorer/
RUN pip3 install pip --upgrade
RUN pip3 install -r /opt/apiexplorer/requirements.txt
WORKDIR /opt/apiexplorer

# Start app in unix socket mode (add "-d" to listen on TCP)
CMD ["python", "run.py"]

