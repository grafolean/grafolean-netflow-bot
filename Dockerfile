FROM python:3.6-slim-stretch as python-requirements
COPY ./Pipfile ./Pipfile.lock /netflowbot/
WORKDIR /netflowbot
RUN \
    pip install pipenv && \
    pipenv lock -r > /requirements.txt

FROM python:3.6-slim-stretch as build-backend
COPY ./ /netflowbot/
WORKDIR /netflowbot
RUN \
    rm -rf .git/ tests/ .vscode/ .pytest_cache/ __pycache__/ && \
    find ./ ! -name '*.py' -type f -exec rm '{}' ';' && \
    python3.6 -m compileall -b ./ && \
    find ./ -name '*.py' -exec rm '{}' ';'


FROM python:3.6-slim-stretch
ARG VERSION
ARG VCS_REF
ARG BUILD_DATE
LABEL org.label-schema.vendor="Grafolean" \
      org.label-schema.url="https://grafolean.com/" \
      org.label-schema.name="Grafolean NetFlow bot" \
      org.label-schema.description="NetFlow collector and Grafolean NetFlow bot" \
      org.label-schema.version=$VERSION \
      org.label-schema.vcs-url="https://github.com/grafolean/grafolean-netflow-bot/" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.docker.schema-version="1.0"
COPY --from=python-requirements /requirements.txt /requirements.txt
RUN \
    pip install --no-cache-dir -r /requirements.txt && \
    echo "alias l='ls -altr'" >> /root/.bashrc
COPY --from=build-backend /netflowbot/ /netflowbot/
WORKDIR /netflowbot
# check for "fail" file and if it exists, remove it and fail the check:
HEALTHCHECK --interval=10s --retries=1 CMD /bin/bash -c "[ ! -f /tmp/fail_health_check ] || ( rm /tmp/fail_health_check && exit 1 )"

# CAREFUL:
# There are three entrypoints, all of which should be running: (use docker-compose.yml to start 3 services)
# - netflowcollector: gathering packets and writing them to named pipe
# - netflowwriter: reading packets from named pipe and writing them to DB
# - netflowbot: Grafolean bot for NetFlow - sending data to Grafolean according to configured sensors
# CMD ["python", "-m", "netflowcollector"]
# CMD ["python", "-m", "netflowwriter"]
CMD ["python", "-m", "netflowbot"]
