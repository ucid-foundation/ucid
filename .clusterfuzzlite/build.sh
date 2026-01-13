#!/bin/bash -eu

pip3 install .

# Build fuzz targets
for fuzzer in $SRC/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
