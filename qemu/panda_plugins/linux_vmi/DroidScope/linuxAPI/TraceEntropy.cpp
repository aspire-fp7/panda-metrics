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
#include <list>
#include <utility>
#include <map>
#include <sys/mman.h> /* TODO: does ARM differ? */
#include <set>
#include <vector>

#include "DroidScope/LinuxAPI.h"
#include "DroidScope/linuxAPI/ProcessInfo.h"
#include "utils/OutputWrapper.h"
#include "panda_plugin.h"
extern "C" {
#include "rr_log.h"
#include "rr_log_all.h"
}

#include "Context.h"

static std::list<ProtectedProgramLocation> current_history;
static int current_length = 0;

/* TODO this is very hacky and temporary */
static uint64_t hashHistory() {
  uint64_t hash = 0x0;
  int i = 0;

  for (auto location : current_history) {
    uint64_t addr;

    if (location.isMobile) {
      addr = ( ((uint64_t)(location.mobile.blockId)) << 32) ^ (uint64_t)location.mobile.offsetInBlock;
    } else {
      addr = (uint64_t)location.libraryOffset;
    }

    hash ^= addr >> 2;
    hash  = (hash << 2) | ((hash >> (64 - 2)) & 0xff);
  }

  return hash;
}

/* Maps locations to a set of (hashes of) traces */
std::map< ProtectedProgramLocation, std::set<uint64_t> > programTraces;

static void updateTraces() {
  /* The location that we will want to insert this trace for is located in the trace at:
     [backward_trace_len] TO UPDATE [forward_trace_len] */
  /* We might might increase the efficiency here if we'd inline the hashHistory in here, as programTraces is a linked list, or store & manipulate some iterators globally! TODO */

  auto loc = current_history.begin();
  for (int i = 0; i < backward_trace_len; i++, ++loc) {
    ; /* TODO this is ugly */
  }

  assert(loc != current_history.end());

  assert((*loc).valid);
  assert(!(*loc).isMobile);

  programTraces[*loc].insert(hashHistory());
}

/* I've observed the following:
   begin of bbl at 0x4009c01c : 0x4009c03b - 0x20 -> offset 0x8101c : 0x8103b
   begin of bbl at 0x4009c038 : 0x4009c043 - 0xc -> offset 0x81038 : 0x81043
   end of bbl at 0x4009c038 : 0x4009c043 - 0xc -> offset 0x81038 : 0x81043
   so I'm assuming that you can get multiple overlapping begins with only a single end, whose size is not the entire size */

static std::map<gpid_t, ProtectedProgramLocation> last_begin_per_process;

int before_block_exec_trace_entropy(CPUState *env, TranslationBlock *tb) {
  if (!shouldTrace(tb->pc))
    return 1;

  ProtectedProgramLocation location = getLocationFor(env, tb->pc);
  if (!location.valid)
    return 1;

  if (last_begin_per_process.find(curProcessPID) == last_begin_per_process.end())
    last_begin_per_process[curProcessPID] = location;

  return 1;
}

int after_block_exec_trace_entropy(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
  if (!shouldTrace(tb->pc))
    return 1;

  auto it = last_begin_per_process.find(curProcessPID);

  /* TODO: thumb mode -2 ! */
  ProtectedProgramLocation location = getLocationFor(env, tb->pc + tb->size - 4);
  if (!location.valid)
    return 1;

  //fprintf(entropy_file, "BBL: 0x%x -> 0x%x\n", it->second.libraryOffset, location.libraryOffset);

  assert(it != last_begin_per_process.end());

  last_begin_per_process.erase(it);

  current_history.push_back(location);
  current_length++;

  /* initially, there is no full history, for now just don't claim these as traces but that might not be the best way, TODO */
  if (current_length == 1 + backward_trace_len + forward_trace_len) {
    updateTraces();
  }

  if (current_length >= 1 + backward_trace_len + forward_trace_len) {
    current_history.pop_front();
    current_length--;
  }

  return 1;
}

void dump_write_entropy_trace() {
  for (auto it: programTraces) {
    assert(it.first.valid);

    if (it.first.isMobile) {
      fprintf(entropy_file, "mobile block %i: offset 0x%x - ", it.first.mobile.blockId, it.first.mobile.offsetInBlock);
    } else {
      fprintf(entropy_file, "library offset 0x%x - ", it.first.libraryOffset);
    }

    fprintf(entropy_file, " => %i different traces\n", it.second.size());
  }
}
