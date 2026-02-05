FROM ghcr.io/base-builder:latest AS base-builder

ENV SRC=/src
RUN mkdir -p $SRC/shellphish

# Shellphish IJON implementation
RUN git clone -b v4.30c  https://github.com/AFLplusplus/AFLplusplus $SRC/shellphish/aflplusplus
COPY aijon/dependencies/clang_indexer/aflpp.diff /tmp/aflpp.diff
RUN cd $SRC/shellphish/aflplusplus && git apply /tmp/aflpp.diff
# # AFL++ IJON implementation
# RUN git clone  https://github.com/AFLplusplus/AFLplusplus $SRC/shellphish/aflplusplus
# COPY aijon/dependencies/clang_indexer/aflpp_new.diff /tmp/aflpp.diff
# RUN cd $SRC/shellphish/aflplusplus && git checkout 93a6e1dbd19da92702dd7393d1cd1b405a6c29ee && git apply /tmp/aflpp.diff

COPY aijon/dependencies/clang_indexer/precompile_shellphish_aijon /usr/local/bin/
RUN /usr/local/bin/precompile_shellphish_aijon

FROM cruizba/ubuntu-dind

RUN apt -y update && apt -y upgrade
RUN apt -y install python3 python3-dev curl git python3-pip rsync jq parallel

RUN pip3 install pyyaml --break-system-packages

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="$PATH:/root/.local/bin"

COPY --from=base-builder /src/shellphish/aflplusplus /src/shellphish/aflplusplus

WORKDIR /aijon

COPY aijon /aijon/aijon
COPY tools /aijon/tools
COPY experiments /aijon/experiments
COPY pyproject.toml /aijon/
COPY main.py /aijon/
COPY builder.py /aijon/
COPY fuzz.py /aijon/
COPY showmap.py /aijon/
COPY reproduce.py /aijon/

# RUN uv run main.py --help

CMD [ "/aijon/tools/runner.sh" ]
