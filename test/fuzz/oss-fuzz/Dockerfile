# The projects/pimd/Dockerfile of google/oss-fuzz, kept here beside the
# build.sh it runs; see README.md in this directory.
FROM gcr.io/oss-fuzz-base/base-builder

# autoconf and automake for autogen.sh; the base image has the rest.
RUN apt-get update && \
    apt-get install -y --no-install-recommends autoconf automake && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/ocochard/pimd.git $SRC/pimd
WORKDIR $SRC/pimd
COPY build.sh $SRC/
