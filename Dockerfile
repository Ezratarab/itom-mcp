# OpenShift-ready image: UBI 9 + Python 3.12, non-root, works with the
# "restricted-v2" SCC (random UID, GID 0) and a read-only root filesystem.

# ---------- build stage: build the wheel ----------
FROM registry.access.redhat.com/ubi9/python-312:latest AS build
USER 1001
WORKDIR /opt/app-root/src
COPY --chown=1001:0 pyproject.toml README.md ./
COPY --chown=1001:0 src ./src
RUN pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel --outdir /tmp/dist

# ---------- runtime stage ----------
FROM registry.access.redhat.com/ubi9/python-312:latest
LABEL name="itom-mcp" \
      summary="ServiceNow ITOM MCP server" \
      io.openshift.expose-services="8080:http"

USER 1001
COPY --from=build /tmp/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl \
 && chmod -R g=u /opt/app-root

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HTTP_HOST=0.0.0.0 \
    MCP_HTTP_PORT=8080 \
    READ_ONLY=true

EXPOSE 8080
ENTRYPOINT ["itom-mcp", "--transport", "http"]
