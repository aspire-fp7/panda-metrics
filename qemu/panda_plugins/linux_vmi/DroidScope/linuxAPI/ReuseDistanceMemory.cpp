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

#include <cassert>
#include <functional>
#include <utility>
#include <map>
#include <sys/mman.h> /* TODO: does ARM differ? */
#include "DroidScope/LinuxAPI.h"
#include "DroidScope/linuxAPI/ProcessInfo.h"
#include "utils/OutputWrapper.h"
#include "panda_plugin.h"

#include "Context.h"

extern "C" {
#include "rr_log.h"
#include "rr_log_all.h"
}

static std::map< AppID, uint64_t > last_write_ticks;

static LocationToLongMap reuse_distances;

/* TODO: other update functions than '<'? :-) */
void updateReuseDistanceMap(ProtectedProgramLocation location, uint64_t previous_write) {
  uint64_t distance = rr_get_guest_instr_count() - previous_write;

  auto it_reuse = reuse_distances.find(location);

  if (it_reuse == reuse_distances.end())
    reuse_distances[location] = distance;
  else if ((*it_reuse).second < distance)
    reuse_distances[location] = distance;
}


int mem_read_callback_reuse_byte(CPUState *env, target_addr_t pc, target_addr_t addr, void *buf) {
  if (!shouldTrace(pc) || !libraryName)
    return 1;

  auto it_write = last_write_ticks.find(getCurrentAppIDLocation(addr));

  if (it_write == last_write_ticks.end()) {
    /* This is mostly for debugging: if there was no value written here yet, don't do anything. Possible false negatives here are data that has been mmaped in (like from the library load),
     * or maybe data from the kernel, not sure about that last one though, depends a bit on the address mapping and the tracing conditions I guess! TODO CHECK that last assumption */
#if 0
    gva_t startAddr, endAddr;
    char modulename[255];
    memset(modulename, 0, 255);
    target_ulong flags;
    int res = getModuleInfoEx(curProcessPID, modulename, 255, &startAddr, &endAddr, pc, NULL, &flags);
    int is_read  = flags & 0x1 ? 1 : 0;
    int is_write = flags & 0x2 ? 1 : 0;
    int is_exec  = flags & 0x4 ? 1 : 0;
    int is_share = flags & 0x8 ? 1 : 0;
    
    int in_range = 1;
    if (pc < startAddr || pc >= endAddr)
      in_range = 0;
    
    if (in_range) {
      if (is_exec) {
	if (is_write) {
	  fprintf(stderr, "WTF, no W^X?\n");
	  fprintf(stderr, "At address 0x" TARGET_FMT_lx ", file '%s', start address 0x" TARGET_FMT_lx " flags = 0x%x, by pc at 0x" TARGET_FMT_lx "\n", addr, modulename, startAddr, flags, pc);
	  printModuleList(stderr, curProcessPID);
	  return 1;
	}
	return 1;
      }
    } else {
      fprintf(stderr, "OUT OF RANGE? \n");
      fprintf(stderr, "At address 0x" TARGET_FMT_lx ", file '%s', start address 0x" TARGET_FMT_lx " flags = 0x%x, by pc at 0x" TARGET_FMT_lx "\n", addr, modulename, startAddr, flags, pc);
      return 1;
    }
#if 0
    fprintf(stderr, "Possibly read-before-write??\n");
    fprintf(stderr, "At address 0x" TARGET_FMT_lx ", file '%s', start address 0x" TARGET_FMT_lx " flags = 0x%x, by pc at 0x" TARGET_FMT_lx "\n", addr, modulename, startAddr, flags, pc);
    printModuleList(stderr, curProcessPID);
#endif
#endif

    return 1;
  }
  
  ProtectedProgramLocation location = getLocationFor(env, pc);
  if (!location.valid)
    return 1;

  updateReuseDistanceMap(location, (*it_write).second);

  return 1;
}

int mem_read_callback_reuse(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf) {
  for (target_addr_t target = addr; target < addr + size; target++) {
    mem_read_callback_reuse_byte(env, pc, target, buf);
  }

  return 1;
}

int mem_write_callback_reuse_byte(CPUState *env, target_addr_t pc, target_addr_t addr, void *buf) {
  /*if (!shouldTrace(pc))
    return 1;*/

  last_write_ticks[getCurrentAppIDLocation(addr)] = rr_get_guest_instr_count();

  return 1;
}

int mem_write_callback_reuse(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf) {
  for (target_addr_t target = addr; target < addr + size; target++) {
    mem_write_callback_reuse_byte(env, pc, target, buf);
  }

  return 1;
}

void dump_write_reuse() {
  for (auto it: reuse_distances) {
    assert(it.first.valid);

    if (it.first.isMobile) {
      fprintf(reuse_file, "mobile block %i: offset 0x" TARGET_FMT_lx " - %" PRIu64 " \n", it.first.mobile.blockId, it.first.mobile.offsetInBlock, it.second);
    } else {
      fprintf(reuse_file, "library offset 0x" TARGET_FMT_lx " - %" PRIu64 " \n", it.first.libraryOffset, it.second);
    }
  }
}
