/**
 * Copyright (C) 2016 Ghent University
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CONTEXT_H
#define __CONTEXT_H

extern FILE* trace_file;
extern FILE* reuse_file;
extern FILE* memory_file;
extern FILE* entropy_file;

extern gpid_t curProcessPID;

typedef target_ulong target_offset_t; /* aka uint32_t */
typedef target_ulong target_addr_t; /* aka uint32_t */

bool shouldTrace(target_addr_t pc);
target_offset_t getFileOffset(target_addr_t pc);

struct MobileCodeInfo {
  int blockId;
  target_addr_t offsetInBlock;
};

static inline bool operator==(const struct MobileCodeInfo& lhs, const struct MobileCodeInfo& rhs) {
  return lhs.blockId == rhs.blockId && lhs.blockId == rhs.blockId;
}

struct ProtectedProgramLocation {
  bool isMobile;
  bool valid;
  union {
    MobileCodeInfo mobile;
    target_offset_t libraryOffset;
  };
};

static inline bool operator==(const struct ProtectedProgramLocation& lhs, const struct ProtectedProgramLocation& rhs) {
  if (!lhs.valid)
    return rhs.valid;
  if (lhs.isMobile && rhs.isMobile)
    return lhs.mobile == rhs.mobile;
  if ( !lhs.isMobile && !rhs.isMobile)
    return lhs.libraryOffset == rhs.libraryOffset;
  return false;
}

/* library code always < mobile code, other comparisons are on their offsets */
static inline bool operator<(const struct ProtectedProgramLocation& lhs, const struct ProtectedProgramLocation& rhs) {
  if ( ! (lhs.valid && rhs.valid) )
    return false;

  if (!lhs.isMobile) {
    if (rhs.isMobile)
      return true;
    return lhs.libraryOffset < rhs.libraryOffset;
  }

  if (rhs.isMobile) {
    if (lhs.mobile.blockId < rhs.mobile.blockId)
      return true;
    if (lhs.mobile.blockId > rhs.mobile.blockId)
      return false;
    return lhs.mobile.offsetInBlock < rhs.mobile.offsetInBlock;
  }

  /* lhs mobile, rhs not mobile => rhs < lhs */
  return false;
}

typedef std::map< ProtectedProgramLocation, uint64_t > LocationToLongMap;

typedef std::pair<gpid_t /* pid TODO asid? */, target_addr_t /* PC addr */> AppID;

static inline AppID getCurrentAppIDLocation(target_addr_t memlocation) {
    return std::make_pair(curProcessPID, memlocation);
}

extern target_offset_t gmrt_offset;
extern target_offset_t gmrt_size;

extern target_offset_t offsetOfFirstInstruction;

extern const char* libraryName;

bool isInMobileBlock(CPUState *env, MobileCodeInfo & info, target_addr_t pc);

/* If the offset indicates that the code location is in the PLT (and thus will not be in Diablo's list file, and thus is about to jump to external code anyway), the valid flag will be true iff isPLTValid */
ProtectedProgramLocation getLocationFor(CPUState *env, target_addr_t pc, bool isPLTValid = false);

void dump_syscall(CPUState *env, target_addr_t pc, ProcessInfo* info);
int mem_write_callback_constness(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf);
void dump_write_constness();

int mem_read_callback_reuse(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf);
int mem_write_callback_reuse(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf);
void dump_write_reuse();

extern int backward_trace_len;
extern int forward_trace_len;

int before_block_exec_trace_entropy(CPUState *env, TranslationBlock *tb);
int after_block_exec_trace_entropy(CPUState *env, TranslationBlock *tb, TranslationBlock *next);
void dump_write_entropy_trace();


#endif /* __CONTEXT_H */
