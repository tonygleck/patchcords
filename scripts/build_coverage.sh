#!/bin/bash

# Licensed under the MIT license. See LICENSE file in the project root for full license information.

set -e

script_dir=$(cd "$(dirname "$0")" && pwd)
root_dir=$(cd "${script_dir}/.." && pwd)
build_dir=$root_dir"/cmake/build"
coverage_dir=$build_dir"/coverage"

rm -rf -f $build_dir
mkdir -p $build_dir
mkdir -p $coverage_dir
pushd $build_dir

cmake -Dpatchcords_ut:BOOL=ON -Denable_tls_lib=ON -DCMAKE_BUILD_TYPE=Debug ../..
make -j
ctest -C "debug" -V -T memcheck

pushd $coverage_dir

# run gcov on the .gcno files
find ../tests/*/*/*/*/*/src/ -name "*.gcno" ! -iname "app_logging.c.gcno" -exec gcov {} . \;

popd
popd
: