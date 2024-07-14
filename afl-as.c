/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - wrapper for GNU as
   ---------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   The sole purpose of this wrapper is to preprocess assembly files generated
   by GCC / clang and inject the instrumentation bits included from afl-as.h. It
   is automatically invoked by the toolchain when compiling programs using
   afl-gcc / afl-clang.

   Note that it's an explicit non-goal to instrument hand-written assembly,
   be it in separate .s files or in __asm__ blocks. The only aspiration this
   utility has right now is to be able to skip them gracefully and allow the
   compilation process to continue.

   That said, see experimental/clang_asm_normalize/ for a solution that may
   allow clang users to make things work even with hand-crafted assembly. Just
   note that there is no equivalent for GCC.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include "afl-as.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>

static u8** as_params;          /* Parameters passed to the real 'as'   */

static u8*  input_file;         /* Originally specified input file      */
static u8*  modified_file;      /* Instrumented file for the real 'as'  */

static u8   be_quiet,           /* Quiet mode (no stderr output)        */
            clang_mode,         /* Running in clang mode?               */
            pass_thru,          /* Just pass data through?              */
            just_version,       /* Just show version?                   */
            sanitizer;          /* Using ASAN / MSAN                    */

static u32  inst_ratio = 100,   /* Instrumentation probability (%)      */
            as_par_cnt = 1;     /* Number of params to 'as'             */

/* If we don't find --32 or --64 in the command line, default to 
   instrumentation for whichever mode we were compiled with. This is not
   perfect, but should do the trick for almost all use cases. */

#ifdef WORD_SIZE_64

static u8   use_64bit = 1;

#else

static u8   use_64bit = 0;

#ifdef __APPLE__
#  error "Sorry, 32-bit Apple platforms are not supported."
#endif /* __APPLE__ */

#endif /* ^WORD_SIZE_64 */


/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

/**
 * @brief 编辑参数并处理环境变量
 *
 * 此函数用于根据命令行参数和环境变量调整编译参数。
 * 它特别处理了 MacOS 上使用 clang 编译器的情况，
 * 并为不同的架构设置参数。
 *
 * @param argc 命令行参数的数量
 * @param argv 指向命令行参数的字符串数组
 */
static void edit_params(int argc, char** argv) {

  // 获取 TMPDIR 和 AFL_AS 环境变量
  u8 *tmp_dir = getenv("TMPDIR"), *afl_as = getenv("AFL_AS");
  u32 i;

#ifdef __APPLE__
  // 标记是否使用 clang 作为汇编器
  u8 use_clang_as = 0;

  // 在 MacOS 上，Xcode 的 'as' 驱动可能不兼容手建的 clang 版本。
  // 如果使用 clang 且未指定 AFL_AS，则调用 'clang -c' 而不是 'as -q'。
  if (clang_mode && !afl_as) {

    use_clang_as = 1;

    // 尝试从环境变量获取 clang 的路径
    afl_as = getenv("AFL_CC");
    if (!afl_as) afl_as = getenv("AFL_CXX");
    if (!afl_as) afl_as = "clang";

  }
#endif

  // 如果 TMPDIR 未设置，则尝试 TEMP 或 TMP，最后默认为 /tmp
  if (!tmp_dir) tmp_dir = getenv("TEMP");
  if (!tmp_dir) tmp_dir = getenv("TMP");
  if (!tmp_dir) tmp_dir = "/tmp";

  // 分配内存给汇编器参数
  as_params = ck_alloc((argc + 32) * sizeof(u8*));

  // 设置汇编器，默认为 'as'
  as_params[0] = afl_as ? afl_as : (u8*)"as";

  // 初始化参数计数器
  as_params[argc] = 0;

  // 遍历命令行参数
  for (i = 1; i < argc - 1; i++) {

    // 处理架构选项
    if (!strcmp(argv[i], "--64")) use_64bit = 1;
    else if (!strcmp(argv[i], "--32")) use_64bit = 0;

#ifdef __APPLE__
    // 特殊处理 MacOS 架构选项
    if (!strcmp(argv[i], "-arch") && i + 1 < argc) {
      if (!strcmp(argv[i + 1], "x86_64")) use_64bit = 1;
      else if (!strcmp(argv[i + 1], "i386"))
        FATAL("Sorry, 32-bit Apple platforms are not supported.");
    }

    // 在使用 clang 时，移除特定选项
    if (clang_mode && (!strcmp(argv[i], "-q") || !strcmp(argv[i], "-Q")))
      continue;
#endif

    // 添加参数到汇编器参数列表
    as_params[as_par_cnt++] = argv[i];

  }

#ifdef __APPLE__
  // 如果使用 clang 作为上游汇编器，附加特定选项
  if (use_clang_as) {
    as_params[as_par_cnt++] = "-c";
    as_params[as_par_cnt++] = "-x";
    as_params[as_par_cnt++] = "assembler";
  }
#endif

  // 设置输入文件
  input_file = argv[argc - 1];

  // 处理特殊输入文件名
  if (input_file[0] == '-') {
    if (!strcmp(input_file + 1, "-version")) {
      just_version = 1;
      modified_file = input_file;
      goto wrap_things_up;
    }
    if (input_file[1]) FATAL("Incorrect use (not called through afl-gcc?)");
    else input_file = NULL;
  } else {
    // 检查是否为标准编译调用
    if (strncmp(input_file, tmp_dir, strlen(tmp_dir)) &&
        strncmp(input_file, "/var/tmp/", 9) &&
        strncmp(input_file, "/tmp/", 5)) pass_thru = 1;
  }

  // 创建临时输出文件名
  modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(), (u32)time(NULL));

wrap_things_up:
  // 添加输出文件名到参数列表
  as_params[as_par_cnt++] = modified_file;
  // 终止参数列表
  as_params[as_par_cnt]   = NULL;

}


/* Process input file, generate modified_file. Insert instrumentation in all
   the appropriate places. */

/**
 * 函数功能：向源代码中添加调试仪器。
 * 
 * 该函数通过读取输入文件（或标准输入），对汇编代码进行处理，并将处理后的代码写入到修改后的文件中。
 * 主要关注点是在代码中合适的位置插入调试仪器，以方便后续的调试和分析工作。
 * 
 * 具体处理包括：
 * - 对代码段的识别，只在.text节中插入仪器。
 * - 忽略某些特定的代码块，如Intel语法、手工汇编代码等。 
 * - 在函数入口、条件跳转指令后和某些标签处插入仪器。
 * 
 * 参数：
 * 无参数。
 * 
 * 返回值：
 * 无返回值。
 */
static void add_instrumentation(void) {

  /* 定义一个静态数组，用于存储从输入文件读取的每一行代码。 */
  static u8 line[MAX_LINE];

  /* 输入文件和输出文件的指针。 */
  FILE* inf;
  FILE* outf;
  /* 输出文件的文件描述符。 */
  s32 outfd;
  /* 记录已插入仪器的行数。 */
  u32 ins_lines = 0;

  /* 各种标志变量，用于控制代码处理的逻辑。 */
  u8  instr_ok = 0, skip_csect = 0, skip_next_label = 0,
      skip_intel = 0, skip_app = 0, instrument_next = 0;

  /* 针对Apple系统的特定处理。 */
#ifdef __APPLE__
  u8* colon_pos;
#endif /* __APPLE__ */

  /* 如果指定了输入文件，则打开它；否则默认读取标准输入。 */
  if (input_file) {
    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);
  } else {
    inf = stdin;
  }

  /* 创建并打开输出文件，确保其唯一性。 */
  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);
  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);
  outf = fdopen(outfd, "w");
  if (!outf) PFATAL("fdopen() failed");

  /* 遍历输入文件的每一行。 */
  while (fgets(line, MAX_LINE, inf)) {
    /* 在特定条件下，插入仪器代码。 */
    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {
      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));
      instrument_next = 0;
      ins_lines++;
    }
    /* 将当前行写入输出文件。 */
    fputs(line, outf);

    /* 如果处于直通模式，则不进行进一步处理。 */
    if (pass_thru) continue;

    /* 处理汇编代码中的节声明，识别.text节并启用/禁用仪器插入。 */
    if (line[0] == '\t' && line[1] == '.') {
      /* 对于OpenBSD的特殊处理，跳过紧接着p2align指令的标签。 */
      if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
          isdigit(line[10]) && line[11] == '\n') skip_next_label = 1;
      /* 检测并标记.text节，启用仪器插入。 */
      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {
        instr_ok = 1;
        continue;
      }
      /* 检测其他节声明，禁用仪器插入。 */
      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "section ", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        instr_ok = 0;
        continue;
      }
    }

    /* 处理不同架构的代码标记，以及跳过手工汇编代码块。 */
    if (strstr(line, ".code")) {
      if (strstr(line, ".code32")) skip_csect = use_64bit;
      if (strstr(line, ".code64")) skip_csect = !use_64bit;
    }
    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;
    if (line[0] == '#' || line[1] == '#') {
      if (strstr(line, "#APP")) skip_app = 1;
      if (strstr(line, "#NO_APP")) skip_app = 0;
    }

    /* 在合适的条件下，检测并标记需要插入仪器的跳转指令和标签。 */
    if (skip_intel || skip_app || skip_csect || !instr_ok ||
        line[0] == '#' || line[0] == ' ') continue;
    if (line[0] == '\t') {
      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {
        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));
        ins_lines++;
      }
      continue;
    }
#ifdef __APPLE__
    if ((colon_pos = strstr(line, ":"))) {
      if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {
#else
    if (strstr(line, ":")) {
      if (line[0] == '.') {
#endif /* __APPLE__ */
        if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
            && R(100) < inst_ratio) {
          if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;
        }
      } else {
        instrument_next = 1;
      }
    }
  }

  /* 如果插入了仪器，则写入主仪器代码。 */
  if (ins_lines)
    fputs(use_64bit ? main_payload_64 : main_payload_32, outf);

  /* 关闭输入和输出文件。 */
  if (input_file) fclose(inf);
  fclose(outf);

  /* 根据插入的仪器数量，输出相应的消息。 */
  if (!be_quiet) {
    if (!ins_lines) WARNF("No instrumentation targets found%s.",
                          pass_thru ? " (pass-thru mode)" : "");
    else OKF("Instrumented %u locations (%s-bit, %s mode, ratio %u%%).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" :
             (sanitizer ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio);
  }

}
/* Main entry point */
/* 主函数入口 */
int main(int argc, char** argv) {

  /* 定义进程ID，用于随机数生成 */
  s32 pid;
  /* 定义随机数种子 */
  u32 rand_seed;
  /* 定义进程状态变量，用于waitpid函数 */
  int status;
  /* 获取环境变量AFL_INST_RATIO，用于控制 instrumentation 的比例 */
  u8* inst_ratio_str = getenv("AFL_INST_RATIO");

  /* 定义时间结构体，用于获取当前时间 */
  struct timeval tv;
  /* 定义时区结构体，用于获取本地时区 */
  struct timezone tz;

  /* 根据环境变量CLANG_ENV_VAR决定是否处于Clang模式 */
  clang_mode = !!getenv(CLANG_ENV_VAR);

  /* 如果标准错误是终端并且没有设置AFL_QUIET环境变量，输出欢迎信息 */
  if (isatty(2) && !getenv("AFL_QUIET")) {
    SAYF(cCYA "afl-as " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  } else {
    /* 否则，设置安静模式 */
    be_quiet = 1;
  }

  /* 如果命令行参数少于2个，显示帮助信息并退出 */
  if (argc < 2) {
    SAYF("\n"
         "This is a helper application for afl-fuzz. It is a wrapper around GNU 'as',\n"
         "executed by the toolchain whenever using afl-gcc or afl-clang. You probably\n"
         "don't want to run this program directly.\n\n"
 
         "Rarely, when dealing with extremely complex projects, it may be advisable to\n"
         "set AFL_INST_RATIO to a value less than 100 in order to reduce the odds of\n"
         "instrumenting every discovered branch.\n\n");
    exit(1);
  }

  /* 获取当前时间，用于生成随机数种子 */
  gettimeofday(&tv, &tz);

  /* 生成随机数种子 */
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  /* 初始化随机数生成器 */
  srandom(rand_seed);

  /* 处理命令行参数 */
  edit_params(argc, argv);

  /* 如果设置了AFL_INST_RATIO环境变量，解析并校验其值 */
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 0 and 100)");
  }

  /* 如果环境变量AS_LOOP_ENV_VAR已设置，表示无限循环问题，报错退出 */
  if (getenv(AS_LOOP_ENV_VAR))
    FATAL("Endless loop when calling 'as' (remove '.' from your PATH)");

  /* 设置AS_LOOP_ENV_VAR环境变量，标记已执行 */
  setenv(AS_LOOP_ENV_VAR, "1", 1);

  /* 如果使用ASAN或MSAN，调整instrumentation比例 */
  if (getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) {
    sanitizer = 1;
    inst_ratio /= 3;
  }

  /* 如果不是仅输出版本信息，添加instrumentation代码 */
  if (!just_version)
    add_instrumentation();

  /* 创建子进程，执行as参数指定的程序 */
  if (!(pid = fork())) {
    execvp(as_params[0], (char**)as_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);
  }

  /* 检查fork是否失败 */
  if (pid < 0) PFATAL("fork() failed");

  /* 等待子进程结束 */
  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  /* 如果没有设置AFL_KEEP_ASSEMBLY环境变量，删除修改后的文件 */
  if (!getenv("AFL_KEEP_ASSEMBLY")) unlink(modified_file);

  /* 退出程序，返回子进程的状态 */
  exit(WEXITSTATUS(status));

}

/*
为什么在汇编过程中要fork创建子程序？

在汇编过程中使用fork创建子进程的主要原因是为了将实际的汇编工作（例如，使用GNU汇编器as）与afl-as脚本的其余部分（如参数处理、环境变量检查、代码覆盖率跟踪添加等）隔离开来。这样做有几个好处：

隔离性：子进程是一个独立的执行环境，它不会继承父进程（即afl-as）的某些设置或状态。这有助于确保汇编器在一个干净的环境中运行，不受父进程可能存在的任何潜在问题的影响。

错误处理：如果汇编器执行失败（例如，由于语法错误、找不到文件等原因），子进程将终止，而父进程（afl-as）可以继续执行清理工作（如删除临时文件）并报告错误。这使得错误处理更加清晰和可管理。

并行性（虽然在这个特定的上下文中可能不相关）：虽然在这个特定的场景中可能没有直接利用并行性，但使用fork和exec系列函数是UNIX和类UNIX系统中创建新进程以执行不同任务的标准方法。这种方法允许在单个程序中进行更复杂的并发和并行处理（如果需要的话）。

安全性：在某些情况下，直接调用外部程序可能会带来安全风险（例如，通过执行恶意代码或访问敏感数据）。虽然在这个场景中，afl-as是专门设计来与可信的汇编器一起工作的，但使用子进程可以作为一种额外的安全层，防止潜在的代码注入攻击。

灵活性：通过使用子进程，afl-as可以更容易地替换或更新用于汇编的底层工具（如GNU汇编器as），而无需修改整个脚本。这增加了代码的模块化和可维护性。

在这个特定的afl-as脚本中，fork用于创建一个子进程，该子进程使用execvp系统调用来执行由as_params数组指定的程序（通常是GNU汇编器as）。如果execvp成功，则子进程将替换为其指定的新程序，并且不会返回到afl-as。如果execvp失败（例如，由于找不到指定的程序），则子进程将打印一条错误消息并退出。父进程（afl-as）将继续执行，检查fork是否成功，等待子进程结束，并执行任何必要的清理工作。
 */