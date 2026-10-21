/* Copyright (c) 2026 VillageSQL Contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

// Minimal in-process server setup for fuzz targets that link
// server_unittest_library. Modeled on setup_server_for_unit_tests() in
// unittest/gunit/test_utils.cc, but with paths resolved at run time, since
// ClusterFuzz runs the fuzzers without the build tree.

#ifndef VILLAGESQL_FUZZ_FUZZ_SERVER_H_
#define VILLAGESQL_FUZZ_FUZZ_SERVER_H_

#include <string>

class THD;

namespace villagesql_fuzz {

// Initialize the server subsystems once and create a THD for the calling
// thread. Call from LLVMFuzzerInitialize.
void init_server(const char *argv0);

// The fuzzing THD, with its stack base reset to the caller's frame.
THD *enter_thd();

// Reset the THD after a statement or VEB operation.
void reset_thd(THD *thd);

// A fresh private directory under $TMPDIR (or /tmp).
std::string make_temp_dir(const char *tag);

}  // namespace villagesql_fuzz

#endif  // VILLAGESQL_FUZZ_FUZZ_SERVER_H_
