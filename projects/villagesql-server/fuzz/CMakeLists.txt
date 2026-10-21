# Copyright (c) 2026 VillageSQL Contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# VillageSQL fuzz targets. OSS-Fuzz's build.sh copies this directory into
# unittest/gunit, where server_unittest_library and the server unit-test
# compile definitions are available.

IF(DEFINED ENV{LIB_FUZZING_ENGINE})
  SEPARATE_ARGUMENTS(VSQL_FUZZ_ENGINE UNIX_COMMAND
    "$ENV{LIB_FUZZING_ENGINE}")
ELSE()
  SET(VSQL_FUZZ_ENGINE -fsanitize=fuzzer)
ENDIF()

MYSQL_ADD_EXECUTABLE(villagesql_fuzz_semver
  fuzz_semver.cc
  ${CMAKE_SOURCE_DIR}/villagesql/common/semver.cc
  SKIP_INSTALL
  )
TARGET_LINK_OPTIONS(villagesql_fuzz_semver PRIVATE ${VSQL_FUZZ_ENGINE})

FOREACH(fuzzer sql_parse veb clone_payload)
  MYSQL_ADD_EXECUTABLE(villagesql_fuzz_${fuzzer}
    fuzz_${fuzzer}.cc
    fuzz_server.cc
    ENABLE_EXPORTS
    SKIP_INSTALL
    LINK_LIBRARIES server_unittest_library mysys strings
    )
  ADD_DEPENDENCIES(villagesql_fuzz_${fuzzer} GenError)
  TARGET_LINK_OPTIONS(villagesql_fuzz_${fuzzer} PRIVATE ${VSQL_FUZZ_ENGINE})
  TARGET_INCLUDE_DIRECTORIES(villagesql_fuzz_${fuzzer} SYSTEM PRIVATE
    ${CMAKE_SOURCE_DIR}/extra/libarchive/libarchive-3.8.1/libarchive
    ${CMAKE_BINARY_DIR}/extra/libarchive/libarchive-3.8.1/libarchive)
ENDFOREACH()

TARGET_LINK_LIBRARIES(villagesql_fuzz_clone_payload archive_static)
