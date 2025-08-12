FROM hub.byted.org/base/debian.bookworm.python312 AS base

ARG DEBIAN_FRONTEND noninteractive

SHELL [ "/bin/bash", "-o", "errexit", "-o", "pipefail", "-o", "xtrace", "-c" ]

RUN apt-get update && apt-get install -y --no-install-recommends build-essential

WORKDIR /app

COPY pyproject.toml client_config.json server_config.json .
COPY bytedance bytedance
COPY demo demo

RUN <<EOF
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -e .
EOF

ENV PATH=/app/.venv/bin:$PATH
ENV VIRTUAL_ENV=/app/.venv

CMD [ "python", "demo/server.py" ]
