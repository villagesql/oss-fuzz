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

// Fuzzes validate_cloned_extensions(), which a clone recipient runs on the
// extension payload sent by the donor before any data is transferred.
//
// The VEB directory holds one real bundle, vsql_fuzz.veb (version 1.0.0), so
// that payloads naming it reach the manifest and SHA-256 checks.

#include <archive.h>
#include <archive_entry.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "fuzz_server.h"
#include "sql/mysqld.h"
#include "sql/sql_class.h"
#include "villagesql/veb/sql_extension.h"
#include "villagesql/veb/veb_file.h"

namespace {

void add_file(struct archive *a, const char *path, const std::string &body) {
  struct archive_entry *entry = archive_entry_new();
  archive_entry_set_pathname(entry, path);
  archive_entry_set_size(entry, body.size());
  archive_entry_set_filetype(entry, AE_IFREG);
  archive_entry_set_perm(entry, 0644);
  archive_write_header(a, entry);
  archive_write_data(a, body.data(), body.size());
  archive_entry_free(entry);
}

void write_veb(const std::string &path) {
  struct archive *a = archive_write_new();
  archive_write_set_format_pax_restricted(a);
  if (archive_write_open_filename(a, path.c_str()) != ARCHIVE_OK) {
    fprintf(stderr, "cannot create %s\n", path.c_str());
    abort();
  }
  add_file(a, "manifest.json",
           "{\"name\": \"vsql_fuzz\", \"version\": \"1.0.0\"}");
  add_file(a, "lib/vsql_fuzz.so", "not a shared object");
  archive_write_close(a);
  archive_write_free(a);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***argv) {
  villagesql_fuzz::init_server((*argv)[0]);

  std::string veb_dir = villagesql_fuzz::make_temp_dir("clone_veb");
  write_veb(veb_dir + "/vsql_fuzz.veb");
  snprintf(opt_veb_dir, FN_REFLEN, "%s/", veb_dir.c_str());
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  THD *thd = villagesql_fuzz::enter_thd();

  std::string payload(reinterpret_cast<const char *>(data), size);
  std::string error_message;
  villagesql::veb::validate_cloned_extensions(thd, payload, &error_message);

  villagesql_fuzz::reset_thd(thd);
  return 0;
}
