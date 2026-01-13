#!/bin/bash -eu

# Install package from local source with no external deps
# This is hash-verified via the pyproject.toml version pinning
pip3 install --no-deps .

# Build fuzz targets
for fuzzer in $SRC/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
