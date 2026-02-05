ARG BASE_IMAGE=
FROM gcr.io/oss-fuzz-base/base-builder AS prebuild

RUN mkdir -p /shellphish/blobs

RUN mkdir -p /shellphish/blobs/offline-packages
RUN apt-get update && apt-get install --download-only --yes \
    -o Dir::Cache::archives="/shellphish/blobs/offline-packages" \
    python3-pip python-is-python3 software-properties-common git \
    libclang1-18 libclang-common-18-dev libspdlog-dev

# both joblib and clang doesn't have dependencies
RUN mkdir -p /shellphish/blobs/pypi-packages
RUN pip download joblib clang==18.1.8 \
    -d /shellphish/blobs/pypi-packages/

# This arg does nothing but force layer cache to be invalidated
ARG BEAR_CACHE_TIMESTAMP=1748543780
RUN wget -q https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/bear -O /shellphish/blobs/bear
RUN wget -q https://raw.githubusercontent.com/a3c1dd56-ce26-4695-aa35-01bc566eb8d4/70261b66-88f0-4957-9568-2dba2faf0916/refs/heads/main/bear.tar.gz -O /shellphish/blobs/bear.tar.gz

FROM ${BASE_IMAGE}

COPY --from=prebuild /shellphish/blobs/offline-packages /shellphish/blobs/offline-packages
RUN cd /shellphish/blobs/offline-packages && \
    apt install -y ./*.deb

RUN git config --global --add safe.directory '*'
RUN mkdir -p /src/shellphish

COPY clang_indexer /src/shellphish/clang-indexer
COPY --from=prebuild /shellphish/blobs/pypi-packages /shellphish/blobs/pypi-packages
RUN pip install --no-index --find-links=/shellphish/blobs/pypi-packages \
    joblib clang==18.1.8 && \
    pip install -e /src/shellphish/clang-indexer

# Bear
COPY --from=prebuild /shellphish/blobs/bear /usr/local/bin/bear
COPY --from=prebuild /shellphish/blobs/bear.tar.gz .
COPY bear_config.json /bear_config.json
RUN tar -xf bear.tar.gz -C /usr/local/lib/ && \
    chmod +x /usr/local/lib/bear/wrapper && \
    chmod +x /usr/local/bin/bear

RUN mv /usr/local/bin/compile /usr/local/bin/compile.old
COPY compile /usr/local/bin/compile
