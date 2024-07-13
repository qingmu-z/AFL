/*
  Copyright 2016 Google LLC All rights reserved.

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

   american fuzzy lop - extract tokens passed to strcmp / memcmp
   -------------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This Linux-only companion library allows you to instrument strcmp(),
   memcmp(), and related functions to automatically extract tokens.
   See README.tokencap for more info.
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "../types.h"
#include "../config.h"

#ifndef __linux__
#  error "Sorry, this library is Linux-specific for now!"
#endif /* !__linux__ */


/* Mapping data and such */

#define MAX_MAPPINGS 1024

static struct mapping {
  void *st, *en;
} __tokencap_ro[MAX_MAPPINGS];

static u32   __tokencap_ro_cnt;
static u8    __tokencap_ro_loaded;
static FILE* __tokencap_out_file;


/* Identify read-only regions in memory. Only parameters that fall into these
   ranges are worth dumping when passed to strcmp() and so on. Read-write
   regions are far more likely to contain user input instead. */

/**
 * @brief 加载映射
 *
 * 从 /proc/self/maps 文件中加载内存映射信息，并解析出只读段的相关信息，将其存储在 __tokencap_ro 数组中。
 *
 * @note 该函数为静态函数，仅供内部使用。
 */
static void __tokencap_load_mappings(void) {
  // 定义一个大小为MAX_LINE的字节数组buf用于存储从文件中读取的每一行数据
  u8 buf[MAX_LINE];
  // 打开/proc/self/maps文件，以只读方式打开
  FILE* f = fopen("/proc/self/maps", "r");

  // 标记__tokencap_ro_loaded为1，表示__tokencap_ro相关的映射已加载
  __tokencap_ro_loaded = 1;

  // 如果文件打开失败，则直接返回
  if (!f) return;

  // 循环读取文件中的每一行数据
  while (fgets(buf, MAX_LINE, f)) {

    // 定义rf和wf变量用于存储读取到的读写权限信息
    u8 rf, wf;
    // 定义st和en变量用于存储读取到的内存地址范围
    void* st, *en;

    // 使用sscanf函数从buf中解析出内存地址范围和读写权限信息
    // 如果解析失败，则继续下一次循环
    if (sscanf(buf, "%p-%p %c%c", &st, &en, &rf, &wf) != 4) continue;
    // 如果写权限为w或者读权限不为r，则继续下一次循环
    if (wf == 'w' || rf != 'r') continue;

    // 将解析出的内存地址范围存储到__tokencap_ro数组中
    __tokencap_ro[__tokencap_ro_cnt].st = (void*)st;
    __tokencap_ro[__tokencap_ro_cnt].en = (void*)en;

    // 更新__tokencap_ro_cnt的计数
    // 如果达到MAX_MAPPINGS的最大值，则跳出循环
    if (++__tokencap_ro_cnt == MAX_MAPPINGS) break;

  }

  // 关闭文件
  fclose(f);

}


/* Check an address against the list of read-only mappings. */

/**
 * @brief 判断给定的指针是否为只读区域
 *
 * 根据给定的指针，判断其是否指向一个只读区域。
 *
 * @param ptr 指针
 *
 * @return 如果指针指向只读区域，则返回1；否则返回0。
 */
static u8 __tokencap_is_ro(const void* ptr) {

  u32 i;

  // 如果__tokencap_ro_loaded为假，则加载映射
  if (!__tokencap_ro_loaded) __tokencap_load_mappings();

  // 遍历__tokencap_ro数组
  for (i = 0; i < __tokencap_ro_cnt; i++) 
    // 如果ptr在__tokencap_ro[i]的起始地址和结束地址之间，则返回1
    if (ptr >= __tokencap_ro[i].st && ptr <= __tokencap_ro[i].en) return 1;

  // 遍历完所有元素后仍未找到匹配的，返回0
  return 0;

}


/* Dump an interesting token to output file, quoting and escaping it
   properly. */

/**
 * __tokencap_dump函数用于将给定的字节序列转换为C语言字符串格式，并写入到指定的输出文件中。
 * 这个函数主要处理非打印字符和特殊字符，将它们转换为转义序列。
 * 
 * @param ptr 指向待处理字节序列的指针。
 * @param len 字节序列的长度。
 * @param is_text 标志位，表示字节序列是否为文本类型。如果为1，则遇到0字节时函数终止处理。
 */
static void __tokencap_dump(const u8* ptr, size_t len, u8 is_text) {
  /* 定义一个缓冲区，用于存储转换后的C语言字符串。 */
  u8 buf[MAX_AUTO_EXTRA * 4 + 1];
  /* 定义一个索引变量，用于在缓冲区中定位。 */
  u32 i;
  /* 定义一个位置变量，用于记录当前在缓冲区中的位置。 */
  u32 pos = 0;

  /* 检查输入字节序列的长度是否在有效范围内，以及是否有指定的输出文件。如果不满足条件，则直接返回。 */
  if (len < MIN_AUTO_EXTRA || len > MAX_AUTO_EXTRA || !__tokencap_out_file)
    return;

  /* 遍历输入的字节序列。 */
  for (i = 0; i < len; i++) {
    /* 如果是文本类型，并且遇到0字节，则终止处理。 */
    if (is_text && !ptr[i]) break;

    /* 根据当前字节的值，决定如何处理。 */
    switch (ptr[i]) {
      /* 对于控制字符、非打印字符、双引号和反斜杠，转换为转义序列。 */
      case 0 ... 31:
      case 127 ... 255:
      case '\"':
      case '\\':
        /* 使用sprintf将字符转换为转义序列，并更新位置。 */
        sprintf(buf + pos, "\\x%02x", ptr[i]);
        pos += 4;
        break;
      /* 对于其他字符，直接复制到缓冲区。 */
      default:
        buf[pos++] = ptr[i];
    }
  }

  /* 在缓冲区的末尾添加字符串结束符。 */
  buf[pos] = 0;

  /* 将转换后的C语言字符串写入到指定的输出文件中。 */
  fprintf(__tokencap_out_file, "\"%s\"\n", buf);    
}


/* Replacements for strcmp(), memcmp(), and so on. Note that these will be used
   only if the target is compiled with -fno-builtins and linked dynamically. */

#undef strcmp

/**
 * 比较两个字符串的字符序列
 * 
 * @param str1 指向第一个字符串的常量指针
 * @param str2 指向第二个字符串的常量指针
 * 
 * @return 当str1和str2相等时，返回0；当str1大于str2时，返回大于0的值；当str1小于str2时，返回小于0的值。
 * 
 * 该函数逐个比较两个字符串中的字符，直到遇到不相等的字符或字符串结束。比较是基于ASCII码值进行的。
 * 如果其中一个字符串是只读的，那么该函数可能会进行额外的操作，这取决于实现的具体细节。
 */
int strcmp(const char* str1, const char* str2) {
  // 如果str1是只读的，则进行某些操作（具体取决于实现），可能是为了安全或调试目的
  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  // 如果str2是只读的，则进行某些操作（具体取决于实现），可能是为了安全或调试目的
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

  // 无限循环，直到找到不相等的字符或其中一个字符串结束
  while (1) {
    // 获取两个字符串当前位置的字符
    unsigned char c1 = *str1, c2 = *str2;
    // 如果两个字符不相等，返回它们的ASCII码值比较结果
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    // 如果当前字符为'\0'，表示两个字符串都结束，返回0表示相等
    if (!c1) return 0;
    // 移动到下一个字符
    str1++; str2++;
  }
}


#undef strncmp

/**
 * 比较两个字符串的前n个字符
 * 
 * 该函数比较两个字符串str1和str2的前n个字符，不考虑字符的大小写。
 * 如果两个字符串在前n个字符内相等，则返回0；如果str1的前n个字符大于str2的前n个字符，
 * 则返回一个正数；如果str1的前n个字符小于str2的前n个字符，则返回一个负数。
 * 
 * @param str1 指向要比较的第一个字符串的指针
 * @param str2 指向要比较的第二个字符串的指针
 * @param len 指定要比较的字符数
 * @return 如果两个字符串在前n个字符内相等，则返回0；如果str1的前n个字符大于str2的前n个字符，
 *         则返回一个正数；如果str1的前n个字符小于str2的前n个字符，则返回一个负数。
 */
int strncmp(const char* str1, const char* str2, size_t len) {

  /* 如果str1是只读字符串，则进行某些操作（如记录或dump） */
  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  /* 如果str2是只读字符串，则进行某些操作（如记录或dump） */
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

  /* 循环比较指定长度的字符 */
  while (len--) {
    /* 获取str1和str2当前比较位置的字符 */
    unsigned char c1 = *str1, c2 = *str2;

    /* 如果str1的当前字符为0，则说明前n个字符比较结束，返回0表示相等 */
    if (!c1) return 0;
    /* 如果当前字符不相等，则比较字符大小并返回比较结果 */
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    /* 移动到下一个字符位置 */
    str1++; str2++;
  }

  /* 所有指定字符比较完毕，返回0表示相等 */
  return 0;

}


#undef strcasecmp

int strcasecmp(const char* str1, const char* str2) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, strlen(str1), 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, strlen(str2), 1);

  while (1) {

    unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    if (!c1) return 0;
    str1++; str2++;

  }

}


#undef strncasecmp

int strncasecmp(const char* str1, const char* str2, size_t len) {

  if (__tokencap_is_ro(str1)) __tokencap_dump(str1, len, 1);
  if (__tokencap_is_ro(str2)) __tokencap_dump(str2, len, 1);

  while (len--) {

    unsigned char c1 = tolower(*str1), c2 = tolower(*str2);

    if (!c1) return 0;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    str1++; str2++;

  }

  return 0;

}


#undef memcmp

int memcmp(const void* mem1, const void* mem2, size_t len) {

  if (__tokencap_is_ro(mem1)) __tokencap_dump(mem1, len, 0);
  if (__tokencap_is_ro(mem2)) __tokencap_dump(mem2, len, 0);

  while (len--) {

    unsigned char c1 = *(const char*)mem1, c2 = *(const char*)mem2;
    if (c1 != c2) return (c1 > c2) ? 1 : -1;
    mem1++; mem2++;

  }

  return 0;

}


#undef strstr

char* strstr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle))
    __tokencap_dump(needle, strlen(needle), 1);

  do {
    const char* n = needle;
    const char* h = haystack;

    while(*n && *h && *n == *h) n++, h++;

    if(!*n) return (char*)haystack;

  } while (*(haystack++));

  return 0;

}


#undef strcasestr

char* strcasestr(const char* haystack, const char* needle) {

  if (__tokencap_is_ro(haystack))
    __tokencap_dump(haystack, strlen(haystack), 1);

  if (__tokencap_is_ro(needle))
    __tokencap_dump(needle, strlen(needle), 1);

  do {

    const char* n = needle;
    const char* h = haystack;

    while(*n && *h && tolower(*n) == tolower(*h)) n++, h++;

    if(!*n) return (char*)haystack;

  } while(*(haystack++));

  return 0;

}


/* Init code to open the output file (or default to stderr). */

/**
 * __tokencap_init函数在程序启动时自动执行，其作用是初始化令牌捕获模块。
 * 它的目的是根据环境变量AFL_TOKEN_FILE的设置，打开一个文件用于写入令牌数据。
 * 如果环境变量未设置，或文件打开失败，它将默认使用标准错误输出。
 *
 * @note 该函数利用了GCC的constructor属性，确保其在main函数之前执行。
 */
__attribute__((constructor)) void __tokencap_init(void) {
  /* 从环境变量中获取用于写入令牌数据的文件名 */
  u8* fn = getenv("AFL_TOKEN_FILE");
  
  /* 如果文件名存在，尝试打开文件用于后续写入 */
  if (fn) __tokencap_out_file = fopen(fn, "a");
  
  /* 如果打开文件失败，或者环境变量未设置，使用标准错误输出作为备用 */
  if (!__tokencap_out_file) __tokencap_out_file = stderr;
}

