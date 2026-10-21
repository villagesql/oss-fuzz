#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# VillageSQL is a MySQL 8.4 fork. Two sets of fuzz targets are built:
#  - routertest_fuzz_*: MySQL Router's protocol and URI fuzzers, as built for
#    projects/mysql-server.
#  - villagesql_fuzz_*: VillageSQL's own targets, kept in $SRC/fuzz. They link
#    the server's unit-test library, so they are added under unittest/gunit.

SRCDIR=$SRC/villagesql-server
cp -r $SRC/fuzz $SRCDIR/unittest/gunit/villagesql_fuzz
echo 'ADD_SUBDIRECTORY(villagesql_fuzz)' >> $SRCDIR/unittest/gunit/CMakeLists.txt

BUILD=$WORK/build
mkdir -p $BUILD
cd $BUILD
export MY_SANITIZER="-DWITH_ASAN=ON"
if [[ $SANITIZER = *undefined* ]]; then
    export MY_SANITIZER="-DWITH_UBSAN=ON"
fi
# not handling yet WITH_MSAN nor WITH_TSAN
cmake $SRCDIR -DBUILD_SHARED_LIBS=OFF -Dprotobuf_BUILD_SHARED_LIBS=OFF \
    -DWITH_SSL=system -DCMAKE_INSTALL_PREFIX=$OUT/mysql -DWITH_LD=lld \
    -DWITH_NDB=OFF -DWITH_NDBCLUSTER_STORAGE_ENGINE=OFF \
    -DWITH_SHARED_UNITTEST_LIBRARY=OFF \
    $MY_SANITIZER
FUZZ_TARGETS=$(make help | sed -n 's/^\.\.\. \([^ ]*fuzz[^ ]*\).*/\1/p' | sort -u)
make -j$(nproc) GenError $FUZZ_TARGETS
mkdir -p $OUT/lib/
# Shared libraries the fuzzers load from $ORIGIN/lib (bundled abseil etc.).
cp -P library_output_directory/*.so* $OUT/lib/

# Error message files for the server-linked targets.
mkdir -p $OUT/villagesql_share
cp -r share/english $OUT/villagesql_share/

PROTOCOL_CORPUS=$SRCDIR/router/src/mysql_protocol/tests/corpus
ROUTER_CORPUS=$SRCDIR/router/tests/fuzzers/corpus
(
cd runtime_output_directory/
ls *fuzz* | while read i; do
    cp $i $OUT/
    chrpath -r '$ORIGIN/lib' $OUT/$i || true
    case $i in
        routertest_fuzz_mysql_protocol_*)
            corpus=$PROTOCOL_CORPUS/${i#routertest_fuzz_mysql_protocol_} ;;
        routertest_*)
            corpus=$ROUTER_CORPUS/${i#routertest_} ;;
        *)
            corpus= ;;
    esac
    if [ -n "$corpus" ] && [ -d "$corpus" ]; then
        zip -qj $OUT/${i}_seed_corpus.zip $corpus/*
    fi
done
)

python3 $SRC/fuzz/make_seeds.py $SRCDIR $OUT
