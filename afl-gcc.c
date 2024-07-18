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
   american fuzzy lop - wrapper for GCC and clang
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
static u8   be_quiet,               /* Quiet mode                        */
            clang_mode;             /* Invoked as afl-clang*?            */


/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

/**
 * 查找AFL的汇编器路径。
 * 
 * 该函数旨在确定AFL的汇编器(afl-as)的位置。它首先尝试通过环境变量AFL_PATH来查找。
 * 如果失败，则尝试相对于程序路径来查找。最后，如果都没有找到，将输出错误消息并终止程序。
 * 
 * @param argv0 程序的路径，用于尝试相对查找。
 */
static void find_as(u8* argv0) {
  /* 从环境变量AFL_PATH中获取AFL的路径 */
  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;
  
  /* 如果AFL_PATH存在 */
  if (afl_path) {
    /* 构造AFL汇编器的完整路径 */
    tmp = alloc_printf("%s/as", afl_path);
    
    /* 检查汇编器是否可执行 */
    if (!access(tmp, X_OK)) {
      /* 如果可执行，记录汇编器路径并释放临时字符串 */
      as_path = afl_path;
      ck_free(tmp);
      return;
    }
    
    /* 释放临时字符串 */
    ck_free(tmp);
  }
  
  /* 尝试从程序路径中查找汇编器 */
  slash = strrchr(argv0, '/');
  
  /* 如果找到了路径分隔符 */
  if (slash) {
    u8 *dir;
    /* 截取程序路径直到最后一个斜杠 */
    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';
    
    /* 构造AFL汇编器的可能路径 */
    tmp = alloc_printf("%s/afl-as", dir);
    
    /* 检查汇编器是否可执行 */
    if (!access(tmp, X_OK)) {
      /* 如果可执行，记录目录路径并释放临时字符串 */
      as_path = dir;
      ck_free(tmp);
      return;
    }
    
    /* 释放临时字符串和目录路径 */
    ck_free(tmp);
    ck_free(dir);
  }
  
  /* 尝试使用默认路径/AFL_PATH下的汇编器 */
  if (!access(AFL_PATH "/as", X_OK)) {
    /* 如果可执行，记录默认路径 */
    as_path = AFL_PATH;
    return;
  }
  
  /* 如果所有尝试都失败，输出错误消息并终止程序 */
  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
}


/* Copy argv to cc_params, making the necessary edits. */

/**
 * 编辑参数函数
 * 
 * 该函数用于处理和编辑给定的命令行参数，以适应AFL（American Fuzzy Lop）的需要。
 * 它根据不同的编译器名称和平台选项，动态调整编译参数，以优化模糊测试的性能。
 * 
 * @param argc 命令行参数的数量
 * @param argv 命令行参数的字符串数组
 */
static void edit_params(u32 argc, char** argv) {
  /* 初始化标志变量，用于跟踪是否设置了特定的编译器选项 */
  u8 fortify_set = 0, asan_set = 0;
  u8 *name;

  /* 根据平台定义，初始化32位编译器选项标志 */
#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif

  /* 分配足够的内存来存储调整后的编译器参数 */
  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  /* 获取并处理可执行文件的名称，用于确定使用的编译器 */
  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  /* 根据可执行文件的名称，确定是否使用clang，并设置相应的环境变量和编译器参数 */
  if (!strncmp(name, "afl-clang", 9)) {
    clang_mode = 1;
    setenv(CLANG_ENV_VAR, "1", 1);

    /* 根据可执行文件的具体名称，选择使用clang++或clang */
    if (!strcmp(name, "afl-clang++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
    }

  } else {

    /* 处理在Apple系统上使用afl-gcc、afl-g++、afl-gcj的情况，优先使用环境变量指定的编译器 */
#ifdef __APPLE__
    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX");
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ");
    else cc_params[0] = getenv("AFL_CC");

    /* 如果没有设置环境变量，给出错误提示并退出 */
    if (!cc_params[0]) {
      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");
      FATAL("AFL_CC or AFL_CXX required on MacOS X");
    }
#else
    /* 处理在非Apple系统上使用afl-gcc、afl-g++、afl-gcj的情况，优先使用环境变量指定的编译器 */
    if (!strcmp(name, "afl-g++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
    } else if (!strcmp(name, "afl-gcj")) {
      u8* alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
    }
#endif /* __APPLE__ */

  }

  /* 遍历命令行参数，处理并添加特定的编译器选项 */
  while (--argc) {
    u8* cur = *(++argv);

    /* 处理-B选项，允许用户覆盖默认的汇编器路径 */
    if (!strncmp(cur, "-B", 2)) {
      if (!be_quiet) WARNF("-B is already set, overriding");
      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;
    }

    /* 忽略-integrated-as、-pipe选项，因为AFL不需要这些 */
    if (!strcmp(cur, "-integrated-as")) continue;
    if (!strcmp(cur, "-pipe")) continue;

    /* 根据平台定义，处理-m32选项 */
#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    /* 处理地址和内存 sanitizer 选项，以及FORTIFY_SOURCE宏定义 */
    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory")) asan_set = 1;
    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    /* 添加当前选项到编译器参数列表中 */
    cc_params[cc_par_cnt++] = cur;

  }

  /* 添加AFL的默认-B选项和汇编器路径 */
  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path;

  /* 如果使用clang，添加-no-integrated-as选项以避免问题 */
  if (clang_mode)
    cc_params[cc_par_cnt++] = "-no-integrated-as";

  /* 根据环境变量AFL_HARDEN，添加额外的硬ening选项 */
  if (getenv("AFL_HARDEN")) {
    cc_params[cc_par_cnt++] = "-fstack-protector-all";
    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
  }

  /* 根据环境变量AFL_USE_ASAN和AFL_USE_MSAN，配置相应的地址和内存sanitizer选项 */
  if (asan_set) {
    setenv("AFL_USE_ASAN", "1", 1);
  } else if (getenv("AFL_USE_ASAN")) {
    if (getenv("AFL_USE_MSAN"))
      FATAL("ASAN and MSAN are mutually exclusive");
    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");
    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";
  } else if (getenv("AFL_USE_MSAN")) {
    if (getenv("AFL_USE_ASAN"))
      FATAL("ASAN and MSAN are mutually exclusive");
    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");
    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";
  }

  /* 如果没有设置AFL_DONT_OPTIMIZE，添加优化选项以提高模糊测试的性能 */
  if (!getenv("AFL_DONT_OPTIMIZE")) {
#if defined(__FreeBSD__) && defined(__x86_64__)
    /* 在64位FreeBSD系统上，针对clang和-m32的组合，避免触发已知的bug */
    if (!clang_mode || !m32_set)
      cc_params[cc_par_cnt++] = "-g";
#else
    cc_params[cc_par_cnt++] = "-g";
#endif
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* 添加特定的宏定义，以指示正在为模糊测试构建 */
    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";
  }

  /* 如果设置了AFL_NO_BUILTIN，禁用一些内置函数，以增加发现新漏洞的机会 */
  if (getenv("AFL_NO_BUILTIN")) {
    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";
  }

  /* 结束参数列表 */
  cc_params[cc_par_cnt] = NULL;
}


/* Main entry point */
/* 主函数：程序的入口点 */
int main(int argc, char** argv) {
  /* 检查标准错误是否连接到终端，且环境变量AFL_QUIET未设置 */
  if (isatty(2) && !getenv("AFL_QUIET")) {
    /* 如果条件满足，打印欢迎信息和版本号 */
    SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  } else {
    /* 否则，设置全局变量be_quiet，以静默模式运行 */
    be_quiet = 1;
  }
  /* 如果命令行参数少于2个，打印帮助信息并退出程序 */
  if (argc < 2) {
    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc or clang, letting you recompile third-party code with the required\n"
         "runtime instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc ./configure\n"
         "  CXX=%s/afl-g++ ./configure\n\n"

         "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
         "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);
    exit(1);
  }
  /* 查找汇编器的路径 */
  find_as(argv[0]);
  /* 修改参数列表，为编译器参数添加必要的修饰 */
  edit_params(argc, argv);
  /* 使用execvp函数替换当前进程为指定的编译器程序 */
  execvp(cc_params[0], (char**)cc_params);
  /* 如果执行失败，打印错误信息并退出程序 */
  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);
  return 0;
}
