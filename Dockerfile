FROM python:3.6

WORKDIR /certmaestro
RUN apt update && apt install --yes mc
COPY certmaestro /certmaestro/certmaestro
COPY setup.py /certmaestro

RUN pip install ipython
RUN pip install -e .
