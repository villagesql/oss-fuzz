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

// Fuzzes VEB (VillageSQL Extension Bundle) handling: the input is written as
// {veb_dir}/fuzz.veb, then read with load_veb_manifest() and unpacked with
// expand_veb_to_directory(), as INSTALL EXTENSION does.
//
// Besides memory errors, this checks that extraction never writes outside the
// expansion cache: after each input, the only entries left in the fuzzing
// directories must be the ones the harness created.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>

#include "fuzz_server.h"
#include "sql/mysqld.h"
#include "sql/sql_class.h"
#include "villagesql/veb/sql_extension.h"
#include "villagesql/veb/veb_file.h"

namespace fs = std::filesystem;

namespace {

std::string g_root;
std::string g_veb_dir;
std::string g_data_dir;

std::set<std::string> list_dir(const std::string &dir) {
  std::set<std::string> names;
  std::error_code ec;
  for (const auto &entry : fs::directory_iterator(dir, ec)) {
    names.insert(entry.path().filename().string());
  }
  return names;
}

void check_no_escape() {
  if (list_dir(g_root) != std::set<std::string>{"data", "veb"} ||
      list_dir(g_veb_dir) != std::set<std::string>{"fuzz.veb"} ||
      !list_dir(g_data_dir).empty()) {
    fprintf(stderr, "VEB extraction left files outside the expansion cache\n");
    abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***argv) {
  villagesql_fuzz::init_server((*argv)[0]);

  g_root = villagesql_fuzz::make_temp_dir("veb");
  g_veb_dir = g_root + "/veb";
  g_data_dir = g_root + "/data";
  fs::create_directory(g_veb_dir);
  fs::create_directory(g_data_dir);

  snprintf(opt_veb_dir, FN_REFLEN, "%s/", g_veb_dir.c_str());
  snprintf(mysql_real_data_home, FN_REFLEN, "%s/", g_data_dir.c_str());
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  THD *thd = villagesql_fuzz::enter_thd();

  {
    std::ofstream veb(g_veb_dir + "/fuzz.veb",
                      std::ios::binary | std::ios::trunc);
    veb.write(reinterpret_cast<const char *>(data), size);
  }

  std::string version;
  villagesql::veb::load_veb_manifest("fuzz", version);

  std::string expanded_path;
  std::string sha256;
  villagesql::veb::expand_veb_to_directory("fuzz", "", expanded_path, sha256);

  std::error_code ec;
  fs::remove_all(g_data_dir + "/.veb_expansion_cache", ec);
  check_no_escape();

  villagesql_fuzz::reset_thd(thd);
  return 0;
}
