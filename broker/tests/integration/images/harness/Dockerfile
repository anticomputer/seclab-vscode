# Test driver: pytest plus the docker CLI. It plays the host side (the fake
# tab supervisor): creates the pod, drives the broker over `docker exec -i`
# stdio, and runs probes inside the workspace container.
FROM docker:29-cli@sha256:4d742ab934c2149b628bf26369ac3ec51cb91e2e28fe6722a0e86a6d6efc4bd5 AS cli

FROM python:3.13-slim-trixie@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1
COPY --from=cli /usr/local/bin/docker /usr/local/bin/docker
COPY tests/integration/images/harness/requirements.txt /opt/harness/requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes -r /opt/harness/requirements.txt
# The protocol definition (and its loader) so every live message is validated against it.
COPY seclab_broker/__init__.py seclab_broker/policy.py seclab_broker/protocol.py /opt/harness/seclab_broker/
COPY schema/policy.v1.schema.json schema/protocol.v1.json /opt/harness/seclab_broker/data/
COPY tests/integration/*.py /opt/harness/
WORKDIR /opt/harness
ENTRYPOINT ["python", "-m", "pytest", "-p", "no:cacheprovider", "-v", "-rfE"]
CMD ["."]
