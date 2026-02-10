ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-slim AS builder
WORKDIR /src

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN python -m pip install --upgrade pip build

COPY pyproject.toml README.md LICENSE /src/

COPY secrets_hunter/ /src/secrets_hunter/

RUN python -m build --wheel

FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd -m -u 10001 appuser \
 && mkdir -p /work \
 && chown -R appuser:appuser /work

WORKDIR /tmp
COPY --from=builder /src/dist/*.whl /tmp/
RUN python -m pip install --upgrade pip \
 && python -m pip install /tmp/*.whl \
 && rm -rf /tmp/*.whl

USER appuser
WORKDIR /work

ENTRYPOINT ["secrets-hunter"]
CMD ["--help"]
