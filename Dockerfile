FROM python:3.6
MAINTAINER Steven Serrata <sserrata@paloaltonetworks.com>

ENV PYTHONUNBUFFERED 1

RUN mkdir -p /opt/apiexplorer
RUN mkdir -p /opt/apiexplorerdb
ADD . /opt/apiexplorer/
RUN pip install pip --upgrade
# RUN pip install pipenv

WORKDIR /opt/apiexplorer
# RUN pipenv install --system --deploy
RUN pip install -r requirements.txt


