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

   american fuzzy lop - dislocator, an abusive allocator
   -----------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This is a companion library that can be used as a drop-in replacement
   for the libc allocator in the fuzzed binaries. See README.dislocator for
   more info.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>

#include "../config.h"
#include "../types.h"

#ifndef PAGE_SIZE
#  define PAGE_SIZE 4096
#endif /* !PAGE_SIZE */

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif /* !MAP_ANONYMOUS */

/* Error / message handling: */

#define DEBUGF(_x...) do { \
    if (alloc_verbose) { \
      if (++call_depth == 1) { \
        fprintf(stderr, "[AFL] " _x); \
        fprintf(stderr, "\n"); \
      } \
      call_depth--; \
    } \
  } while (0)

#define FATAL(_x...) do { \
    if (++call_depth == 1) { \
      fprintf(stderr, "*** [AFL] " _x); \
      fprintf(stderr, " ***\n"); \
      abort(); \
    } \
    call_depth--; \
  } while (0)

/* Macro to count the number of pages needed to store a buffer: */

#define PG_COUNT(_l) (((_l) + (PAGE_SIZE - 1)) / PAGE_SIZE)

/* Canary & clobber bytes: */

#define ALLOC_CANARY  0xAACCAACC
#define ALLOC_CLOBBER 0xCC

// 尝试访问 _p 指针之前一个 u32 大小位置的值。
#define PTR_C(_p) (((u32*)(_p))[-1])
// 尝试访问 _p 指针之前两个 u32 大小位置的值。
#define PTR_L(_p) (((u32*)(_p))[-2])

/* Configurable stuff (use AFL_LD_* to set): */

static u32 max_mem = MAX_ALLOC;         /* Max heap usage to permit         */
static u8  alloc_verbose,               /* Additional debug messages        */
           hard_fail,                   /* abort() when max_mem exceeded?   */
           no_calloc_over;              /* abort() on calloc() overflows?   */

static __thread size_t total_mem;       /* Currently allocated mem          */

static __thread u32 call_depth;         /* To avoid recursion via fprintf() */


/* This is the main alloc function. It allocates one page more than necessary,
   sets that tailing page to PROT_NONE, and then increments the return address
   so that it is right-aligned to that boundary. Since it always uses mmap(),
   the returned memory will be zeroed. */

/**
 * @brief 分配内存
 *
 * 根据给定的长度，分配内存并返回指针。
 *
 * @param len 要分配的内存大小（以字节为单位）
 *
 * @return 成功时返回指向分配的内存的指针，失败时返回NULL
 */
static void* __dislocator_alloc(size_t len) {

  void* ret;

  // 检查是否超出最大内存限制或发生内存溢出
  if (total_mem + len > max_mem || total_mem + len < total_mem) {

    if (hard_fail)
      FATAL("total allocs exceed %u MB", max_mem / 1024 / 1024);

    // 输出调试信息并返回NULL
    DEBUGF("total allocs exceed %u MB, returning NULL",
           max_mem / 1024 / 1024);

    return NULL;

  }

  /* 我们还将在实际缓冲区下方存储缓冲区长度和一个哨兵值，因此需要添加8个字节 */
  /* We will also store buffer length and a canary below the actual buffer, so
     let's add 8 bytes for that. */

  // 使用mmap函数分配内存
  ret = mmap(NULL, (1 + PG_COUNT(len + 8)) * PAGE_SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  // 如果mmap函数失败，返回NULL
  if (ret == (void*)-1) {

    if (hard_fail) FATAL("mmap() failed on alloc (OOM?)");

    DEBUGF("mmap() failed on alloc (OOM?)");

    return NULL;

  }

  // 将最后一页的权限设置为PROT_NONE
  /* Set PROT_NONE on the last page. */

  if (mprotect(ret + PG_COUNT(len + 8) * PAGE_SIZE, PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when allocating memory");

  // 将返回指针偏移到页面边界的右侧对齐位置
  /* Offset the return pointer so that it's right-aligned to the page
     boundary. */

  ret += PAGE_SIZE * PG_COUNT(len + 8) - len - 8;

  // 存储分配元数据
  /* Store allocation metadata. */

  ret += 8;

  // 存储分配的长度
  PTR_L(ret) = len;
  // 存储哨兵值
  PTR_C(ret) = ALLOC_CANARY;

  // 更新已分配内存的总大小
  total_mem += len;

  return ret;

}


/* The "user-facing" wrapper for calloc(). This just checks for overflows and
   displays debug messages if requested. */

/**
 * @brief 动态内存分配（初始化为0）
 *
 * 根据给定的元素长度和元素数量，动态分配内存空间，并将分配的内存区域初始化为0。
 *
 * @param elem_len 每个元素的长度（字节为单位）
 * @param elem_cnt 要分配的元素数量
 *
 * @return 分配并初始化为0的内存区域的指针，如果分配失败则返回NULL
 *
 * @note 执行一些合理性检查以检测明显的问题，如果启用了no_calloc_over标志，则在溢出时返回NULL；
 *       如果未启用该标志，则在溢出时记录致命错误并退出程序。
 */
void* calloc(size_t elem_len, size_t elem_cnt) {

  void* ret;

  size_t len = elem_len * elem_cnt;

  // 执行一些合理性检查以检测明显的问题...
  /* Perform some sanity checks to detect obvious issues... */

  if (elem_cnt && len / elem_cnt != elem_len) {

    // 如果启用了no_calloc_over标志，则直接返回NULL
    if (no_calloc_over) {
      DEBUGF("calloc(%zu, %zu) would overflow, returning NULL", elem_len, elem_cnt);
      return NULL;
    }

    // 如果未启用no_calloc_over标志，则记录致命错误并退出
    FATAL("calloc(%zu, %zu) would overflow", elem_len, elem_cnt);

  }

  // 调用__dislocator_alloc函数分配内存
  ret = __dislocator_alloc(len);

  // 记录分配的内存信息
  DEBUGF("calloc(%zu, %zu) = %p [%zu total]", elem_len, elem_cnt, ret,
         total_mem);

  return ret;

}


/* The wrapper for malloc(). Roughly the same, also clobbers the returned
   memory (unlike calloc(), malloc() is not guaranteed to return zeroed
   memory). */

/**
 * @brief 分配内存
 *
 * 使用自定义的内存分配函数分配指定大小的内存，并返回分配的内存地址。
 *
 * @param len 需要分配的内存大小（字节）
 *
 * @return 成功分配的内存地址指针，若分配失败则返回NULL
 */
void* malloc(size_t len) {

  // 定义一个指向void的指针变量ret
  void* ret;

  // 调用__dislocator_alloc函数分配内存，并将返回值赋值给ret
  ret = __dislocator_alloc(len);

  // 打印调试信息，显示malloc的调用参数、返回值以及总内存使用情况
  DEBUGF("malloc(%zu) = %p [%zu total]", len, ret, total_mem);

  // 如果ret不为空且len大于0，则将ret指向的内存区域的前len个字节填充为ALLOC_CLOBBER
  if (ret && len) memset(ret, ALLOC_CLOBBER, len);

  // 返回分配的内存地址
  return ret;

}


/* The wrapper for free(). This simply marks the entire region as PROT_NONE.
   If the region is already freed, the code will segfault during the attempt to
   read the canary. Not very graceful, but works, right? */

/**
 * @brief 释放内存
 *
 * 释放由内存分配函数分配的内存块。
 *
 * @param ptr 要释放的内存块指针
 */
void free(void* ptr) {

  u32 len;

  // 输出调试信息，打印要释放的内存地址
  DEBUGF("free(%p)", ptr);

  // 如果指针为空，则直接返回
  if (!ptr) return;

  // 检查指针的保护标志是否正确，如果不正确则输出错误信息并终止程序
  if (PTR_C(ptr) != ALLOC_CANARY) FATAL("bad allocator canary on free()");

  // 获取内存块的长度
  len = PTR_L(ptr);

  // 更新总内存使用量，减去要释放的内存块的长度
  total_mem -= len;

  /*
   * 保护整个内存块。注意，末尾的额外页面已经被设置为 PROT_NONE，
   * 所以我们不需要再处理它。
   */
  // 计算要保护的内存块的起始地址
  /* Protect everything. Note that the extra page at the end is already
     set as PROT_NONE, so we don't need to touch that. */
  ptr -= PAGE_SIZE * PG_COUNT(len + 8) - len - 8;

  // 使用 mprotect 函数将内存块的保护级别设置为 PROT_NONE
  if (mprotect(ptr - 8, PG_COUNT(len + 8) * PAGE_SIZE, PROT_NONE))
    FATAL("mprotect() failed when freeing memory");

  /*
   * 保持内存映射不变；这样做是浪费的，但可以防止指针被重用。
   */
  /* Keep the mapping; this is wasteful, but prevents ptr reuse. */

}


/* Realloc is pretty straightforward, too. We forcibly reallocate the buffer,
   move data, and then free (aka mprotect()) the original one. */

/**
 * @brief 重新分配内存
 *
 * 重新分配给定指针指向的内存块的大小，并返回指向新内存块的指针。
 * 如果无法分配足够的内存，则返回 NULL。
 *
 * @param ptr 指向要重新分配的内存块的指针
 * @param len 新的内存块大小（以字节为单位）
 *
 * @return 指向重新分配后的内存块的指针，如果无法分配足够的内存则返回 NULL
 */
void* realloc(void* ptr, size_t len) {

  // 用于保存重新分配内存后返回的地址
  void* ret;

  // 使用 malloc 分配新的内存空间
  ret = malloc(len);

  // 如果新内存地址和原内存地址都不为空
  if (ret && ptr) {

    // 检查原内存地址的分配器金丝雀值是否正确
    // 如果不正确，则输出错误信息并终止程序
    if (PTR_C(ptr) != ALLOC_CANARY) FATAL("bad allocator canary on realloc()");

    // 将原内存地址的内容复制到新内存地址，复制的长度为两者中较小的值
    memcpy(ret, ptr, MIN(len, PTR_L(ptr)));

    // 释放原内存地址
    free(ptr);

  }

  // 输出重新分配内存的相关信息
  DEBUGF("realloc(%p, %zu) = %p [%zu total]", ptr, len, ret, total_mem);

  // 返回重新分配后的内存地址
  return ret;

}


/**
 * @brief 初始化 dislocator
 *
 * 在程序启动时自动调用此函数进行 dislocator 的初始化操作。
 *
 * @note 这是一个带有 constructor 属性的函数，会在程序启动时自动执行。
 */
__attribute__((constructor)) void __dislocator_init(void) {

  // 获取环境变量 "AFL_LD_LIMIT_MB" 的值
  u8* tmp = getenv("AFL_LD_LIMIT_MB");

  if (tmp) {

    // 将字符串转换为整数，并乘以 1024 * 1024，赋值给 max_mem
    max_mem = atoi(tmp) * 1024 * 1024;

    // 如果 max_mem 为 0，则抛出致命错误
    if (!max_mem) FATAL("Bad value for AFL_LD_LIMIT_MB");

  }

  // 判断环境变量 "AFL_LD_VERBOSE" 是否存在，存在则 alloc_verbose 为 1，否则为 0
  alloc_verbose = !!getenv("AFL_LD_VERBOSE");

  // 判断环境变量 "AFL_LD_HARD_FAIL" 是否存在，存在则 hard_fail 为 1，否则为 0
  hard_fail = !!getenv("AFL_LD_HARD_FAIL");

  // 判断环境变量 "AFL_LD_NO_CALLOC_OVER" 是否存在，存在则 no_calloc_over 为 1，否则为 0
  no_calloc_over = !!getenv("AFL_LD_NO_CALLOC_OVER");

}
