#!/bin/bash -eu

# Install required dependencies first
pip3 install pytz python-dateutil numpy h3 pydantic

# Install package from local source
pip3 install --no-deps .

# Build fuzz targets
for fuzzer in $SRC/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
