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

#include "fuzz_server.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <vector>

#include "my_rnd.h"
#include "my_sys.h"
#include "mysql/components/services/log_builtins.h"
#include "mysql/strings/m_ctype.h"
#include "sql/check_stack.h"
#include "sql/dd/impl/dictionary_impl.h"
#include "sql/log.h"
#include "sql/mysqld.h"
#include "sql/opt_costconstantcache.h"
#include "sql/rpl_handler.h"
#include "sql/set_var.h"
#include "sql/sql_class.h"
#include "sql/sql_lex.h"
#include "sql/sql_plugin.h"
#include "sql/xa/transaction_cache.h"
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#include "storage/perfschema/pfs_server.h"
#endif

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/lsan_interface.h>
#define VSQL_FUZZ_HAVE_LSAN 1
#endif
#endif

// Defined in sql/server_component/server_component.cc; mysqld declares it
// the same way.
extern bool initialize_minimal_chassis(SERVICE_TYPE_NO_CONST(registry) *
                                       *registry);

// Same declaration as in unittest/gunit/test_utils.h, which needs gtest.
// Dictionary_impl names this class as a friend; test_utils.cc, which
// normally defines it, is not linked into the fuzzers.
namespace my_testing {
class DD_initializer {
 public:
  static void SetUp();
  static void TearDown();
};

// Query_block::add_table_to_list() asks the dictionary about system views.
// An instance is enough; no dictionary tables are opened.
void DD_initializer::SetUp() {
  dd::Dictionary_impl::s_instance = new dd::Dictionary_impl();
}
}  // namespace my_testing

namespace villagesql_fuzz {

namespace {

THD *g_thd = nullptr;

// Until mysqld sets up its log sinks, error-log events are buffered in
// memory, which would grow without bound over a fuzzing run. Drop them.
bool discard_log_line(log_line *) { return false; }

std::string dirname_of(const char *path) {
  char resolved[PATH_MAX];
  if (realpath(path, resolved) == nullptr) return ".";
  std::string s(resolved);
  size_t slash = s.rfind('/');
  return slash == std::string::npos ? "." : s.substr(0, slash);
}

}  // namespace

std::string make_temp_dir(const char *tag) {
  const char *tmp = getenv("TMPDIR");
  std::string templ = std::string(tmp != nullptr && *tmp ? tmp : "/tmp") +
                      "/villagesql_fuzz_" + tag + "_XXXXXX";
  std::vector<char> buf(templ.begin(), templ.end());
  buf.push_back('\0');
  if (mkdtemp(buf.data()) == nullptr) {
    perror("mkdtemp");
    abort();
  }
  return std::string(buf.data());
}

void init_server(const char *argv0) {
#ifdef VSQL_FUZZ_HAVE_LSAN
  // Server state set up here lives for the whole process and is never torn
  // down; keep it out of LeakSanitizer's report at exit.
  __lsan_disable();
#endif
  initialize_stack_direction();
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  pre_initialize_performance_schema();
#endif
  MY_INIT(argv0);
  log_line_process_hook_set(discard_log_line);

  // The component registry, as in component_infrastructure_init(). Code such
  // as sp_head's destructor looks services up in it.
  if (initialize_minimal_chassis(&srv_registry)) {
    fprintf(stderr, "initialize_minimal_chassis failed\n");
    abort();
  }

  // The server keeps pointers into these, so they live for the process.
  static std::string datadir_arg =
      "--datadir=" + make_temp_dir("datadir");
  static std::string messages_arg =
      "--lc-messages-dir=" + dirname_of(argv0) + "/villagesql_share";
  static std::string progname(my_progname);
  static char *server_argv[] = {
      const_cast<char *>(progname.c_str()),
      const_cast<char *>("--secure-file-priv=NULL"),
      const_cast<char *>("--log_syslog=0"),
      const_cast<char *>("--explicit_defaults_for_timestamp"),
      const_cast<char *>(datadir_arg.c_str()),
      const_cast<char *>(messages_arg.c_str()),
      nullptr};
  set_remaining_args(6, server_argv);
  system_charset_info = &my_charset_utf8mb3_general_ci;

  mysql_mutex_init(PSI_NOT_INSTRUMENTED, &LOCK_plugin, MY_MUTEX_INIT_FAST);
  sys_var_init();
  init_common_variables();
  test_flags |= TEST_NO_TEMP_TABLES;
  randominit(&sql_rand, 0, 0);
  xa::Transaction_cache::initialize();
  delegates_init();
  gtid_server_init();
  // As in mysqld: errors go to the THD's diagnostics area, which is what
  // stops the parser and other callers after an error.
  error_handler_hook = my_message_sql;
  query_logger.init();
  init_optimizer_cost_module(false);
  my_testing::DD_initializer::SetUp();

  g_thd = new THD(false);
  g_thd->set_new_thread_id();
  enter_thd();
  g_thd->store_globals();
  lex_start(g_thd);

  // The THD destructor frees this with my_free().
  char *db = static_cast<char *>(my_malloc(PSI_NOT_INSTRUMENTED, 5, MYF(0)));
  strcpy(db, "fuzz");
  g_thd->reset_db({db, strlen(db)});
#ifdef VSQL_FUZZ_HAVE_LSAN
  __lsan_enable();
#endif
}

THD *enter_thd() {
  THD *stack_thd = g_thd;
  g_thd->thread_stack = reinterpret_cast<char *>(&stack_thd);
  return g_thd;
}

void reset_thd(THD *thd) {
  thd->end_statement();
  thd->cleanup_after_query();
  thd->get_stmt_da()->reset_diagnostics_area();
  thd->get_stmt_da()->reset_condition_info(thd);
  thd->mem_root->ClearForReuse();
}

}  // namespace villagesql_fuzz
