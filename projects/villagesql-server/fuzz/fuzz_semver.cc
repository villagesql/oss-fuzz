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

// Fuzzes villagesql::Semver, which parses the server, schema and extension
// version strings that VillageSQL persists and compares at startup.
//
// Input: two version strings separated by the first newline. Each is parsed
// with parse() and parse_schema_version(); valid results must survive a
// to_string() round trip, and the comparison operators must agree.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "villagesql/include/semver.h"

using villagesql::Semver;

namespace {

void check(bool condition) {
  if (!condition) abort();
}

void check_round_trip(const Semver &v) {
  if (!v.is_valid()) return;
  std::string s = v.to_string();
  Semver again;
  check(again.parse(s));
  check(again == v);
  check(again.build_metadata() == v.build_metadata());
  check(again.to_string() == s);
}

void check_ordering(const Semver &a, const Semver &b) {
  if (!a.is_valid() || !b.is_valid()) return;
  bool lt = a < b;
  bool gt = a > b;
  bool eq = a == b;
  check(!(lt && gt));
  check(lt == (b > a));
  check((a <= b) == (lt || eq));
  check((a >= b) == (gt || eq));
  check(eq != (a != b));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string_view input(reinterpret_cast<const char *>(data), size);
  size_t newline = input.find('\n');
  std::string_view first = input.substr(0, newline);
  std::string_view second =
      newline == std::string_view::npos ? first : input.substr(newline + 1);

  std::string error;
  Semver a, b, schema_a, schema_b;
  a.parse(first, &error);
  b.parse(second, &error);
  schema_a.parse_schema_version(first, &error);
  schema_b.parse_schema_version(second, &error);

  check_round_trip(a);
  check_round_trip(schema_a);
  check_ordering(a, b);
  check_ordering(schema_a, schema_b);
  check_ordering(a, a);
  return 0;
}
