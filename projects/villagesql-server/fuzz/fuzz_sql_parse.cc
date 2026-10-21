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

// Fuzzes the SQL lexer and parser, including VillageSQL's grammar additions
// (INSTALL/UNINSTALL EXTENSION, extension-qualified custom types and
// functions). Statements are parsed into a parse tree but not executed.

#include <cstddef>
#include <cstdint>
#include <string>

#include "fuzz_server.h"
#include "sql/sql_class.h"
#include "sql/sql_lex.h"
#include "sql/sql_parse.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***argv) {
  villagesql_fuzz::init_server((*argv)[0]);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  THD *thd = villagesql_fuzz::enter_thd();

  // The lexer expects a NUL after the query text.
  std::string query(reinterpret_cast<const char *>(data), size);

  Parser_state state;
  if (state.init(thd, query.c_str(), query.size())) return 0;

  lex_start(thd);
  mysql_reset_thd_for_next_command(thd);
  parse_sql(thd, &state, nullptr);
  lex_end(thd->lex);

  villagesql_fuzz::reset_thd(thd);
  return 0;
}
