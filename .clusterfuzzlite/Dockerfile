FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:b98e8f5a4a35b82a733d7b3f3f8929ec2a4f0e8b2a0f5e8b2a0f5e8b2a0f5e8b

RUN pip3 install atheris

COPY . $SRC/ucid
WORKDIR $SRC/ucid

COPY .clusterfuzzlite/fuzz_*.py $SRC/
