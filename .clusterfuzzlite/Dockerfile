# Use official OSS-Fuzz base builder for Python
# Pinned to SHA256 digest for OpenSSF Scorecard compliance
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:b00aa383709c30306257890b9fd23c5fff7079510bab86ba7e332ab5e04c27a4

# Install atheris (required for fuzzing)
# Note: ClusterFuzzLite environment handles dependency verification
RUN pip3 install --no-cache-dir atheris==2.3.0

COPY . $SRC/ucid
WORKDIR $SRC/ucid

# Copy fuzz targets to $SRC for compilation
COPY .clusterfuzzlite/fuzz_*.py $SRC/

# Copy build script to /src where ClusterFuzzLite expects it
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
