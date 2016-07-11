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

#include <functional>
#include <utility>
#include <map>
#include <sys/mman.h> /* TODO: does ARM differ? */
#include "DroidScope/LinuxAPI.h"
#include "DroidScope/linuxAPI/ProcessInfo.h"
#include "utils/OutputWrapper.h"
#include "panda_plugin.h"
extern "C" {
#include "rr_log.h"
#include "rr_log_all.h"
}

#include "Context.h"

/* lowest 8 bits: char value; highest 8 bits: status. 0 -> single value, 1 -> multiple values seen */
static const target_ulong CONST_VALUE_MEM = 0x0;
static const target_ulong TOP_VALUE_MEM = 0x1 << 8;
#define IS_TOP(x) ( ((x) & TOP_VALUE_MEM) == TOP_VALUE_MEM)

static LocationToLongMap written_values;


int mem_write_callback_constness(CPUState *env, target_addr_t pc, target_addr_t addr, target_addr_t size, void *buf) {
  if (!shouldTrace(pc))
    return 1;

  auto write_location = getLocationFor(env, pc);

  for (target_addr_t i = 0; i < size; i++) {
    uint16_t write_value = ((uint8_t*)(buf))[i];

    auto found = written_values.find(write_location); /* TODO this can be optimized if size > 1 as write_pc_pair is always the same! */
    if (found == written_values.end()) {
      /* Insert unique value */
      written_values[write_location] = write_value | CONST_VALUE_MEM;
    } else {
      if (!IS_TOP((*found).second))  {
	if ( ((*found).second & 0xff) != write_value)
	  written_values[write_location] = TOP_VALUE_MEM;
      }
    }
  }

  return 1;
}

void dump_write_constness() {
  //fprintf(memory_file, "DUMPING MEM PRODUCERS...\n");
  for (auto it: written_values) {
    assert(it.first.valid);

    if (it.first.isMobile) {
      fprintf(memory_file, "mobile block %i: offset 0x%x - ", it.first.mobile.blockId, it.first.mobile.offsetInBlock);
    } else {
      fprintf(memory_file, "library offset 0x%x - ", it.first.libraryOffset);
    }

    if (IS_TOP(it.second)) {
      fprintf(memory_file, "TOP\n");
    } else {
      fprintf(memory_file, "0x%x\n", it.second);
    }
  }
  //fprintf(memory_file, "... DONE\n");
}


