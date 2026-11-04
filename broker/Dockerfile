# syntax=docker/dockerfile:1
# seclab-vscode per-tab egress and credential broker.
# Base: official mitmproxy 12.3.1 image (Python 3.15), pinned by manifest-list digest.
FROM mitmproxy/mitmproxy:12.3.1@sha256:2711066c855659b5af8b1dbb84494ed3eff69b42ece439c60b4fe09a2db829d4 AS broker

USER root
COPY requirements.txt /opt/seclab/requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes -r /opt/seclab/requirements.txt \
 && printf '#!/bin/sh\nexec python -m seclab_broker "$@"\n' > /usr/local/bin/seclab-broker \
 && chmod 0755 /usr/local/bin/seclab-broker \
 && install -d -o mitmproxy -g mitmproxy -m 0700 /run/seclab
COPY seclab_broker /opt/seclab/seclab_broker
COPY schema/policy.v1.schema.json schema/protocol.v1.json /opt/seclab/seclab_broker/data/
ENV PYTHONPATH=/opt/seclab PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

USER mitmproxy
EXPOSE 8080
ENTRYPOINT ["seclab-broker"]
CMD ["run"]

# Unit tests run inside the same image plus pytest.
FROM broker AS unit
USER root
COPY requirements-test.txt /opt/seclab/requirements-test.txt
RUN pip install --no-cache-dir --no-deps --require-hashes -r /opt/seclab/requirements-test.txt
COPY tests/unit /opt/seclab/tests/unit
COPY examples /opt/seclab/examples
USER mitmproxy
WORKDIR /opt/seclab
ENTRYPOINT ["python", "-m", "pytest", "-p", "no:cacheprovider", "-q", "tests/unit"]
CMD []
