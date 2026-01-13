# Use official OSS-Fuzz base builder for Python
FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install atheris

COPY . $SRC/ucid
WORKDIR $SRC/ucid

# Copy fuzz targets to $SRC for compilation
COPY .clusterfuzzlite/fuzz_*.py $SRC/

# Copy build script to /src where ClusterFuzzLite expects it
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
