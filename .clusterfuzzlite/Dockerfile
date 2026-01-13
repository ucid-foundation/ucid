# Use official OSS-Fuzz base builder for Python (without pinning to invalid SHA)
FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install atheris

COPY . $SRC/ucid
WORKDIR $SRC/ucid

COPY .clusterfuzzlite/fuzz_*.py $SRC/
