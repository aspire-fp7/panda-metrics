/**
 * Copyright (C) <2011> <Syracuse System Security (Sycure) Lab>
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

/*
 * Context.c
 * The shadow process list and the shadow module list are implemented here. 
 * The flow is something like this:
 * 1. We create an initial process list.
 * 2. We monitor specific system calls (and their respective core functions, e.g. do_fork)
 *   and wait for them to return. Upon return - we update the process list.
 * 2A. While we HOPE to catch all changes to the process list, we might not so
 *       - We create a temporary process list
 *       - Anything NOT in OLD one but in the new one is a new process
 *       - Anything NOT in the NEW one but in the old one has ended
 * 3. The same procedure is used to udpate the modules. The only difference is 
 *      that modules are updated on demand.
 * NOTE: We assume a small number of processes and thus assume that linear
 *   search is perfectly fine. This is different from the PROCMOD approach
 *   that uses multiple hashtables. Hashtables can also be implemented here
 *   as well, but its not too important yet.
 * NOTE: This also means that our shadow process list is very comprehensive.
 *   It is easier and less performance intensive to just keep a pointer to
 *   the guest's task_struct structure per process or thread and read the fields
 *   (e.g. pid, uid, etc.) on demand. However, we update these whenenver the
 *   process list is updated. (Will this reduce the number of changes to the TLB
 *   due since we are reading the memory locations closer to when they were last
 *   used? - I wonder)
 *  Created on: Sep 16, 2011
 *      Author: lok
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

FILE* trace_pc = NULL;

gpid_t curProcessPID = (-1);
static target_asid_t curProcessPGD = 0;

inline gpid_t getCurrentPID(void)
{
  return (curProcessPID);
}

inline target_asid_t getCurrentPGD(void)
{
  return (curProcessPGD);
}

int bSkipNextPGDUpdate = 0;

/************************************************************************
 * Start of implementation section for updating process and module structures
 ************************************************************************/

void updateProcessModuleList(CPUState* env, gpid_t pid)
{
  target_ulong task = 0;
  target_ulong i = 0;
  char name[MAX_PROCESS_INFO_NAME_LEN];

  if (pid == 0)
  {
    return;
  }

  updateModule(pid, -1, 0, 0, NULL, -1);

  task = DECAF_get_current_process(env);
  i = task;
  do
  {
    if (pid == DECAF_get_pid(env, i))
    {
      break;
    }
    i = DECAF_get_next_task_struct(env, i);
  } while ( (i != 0) && (i != task) );

  if ((i == 0) || (i == task))
  {
    return;
  }
  /*if(pid == 31){
      //printf("finding strings for task at 0x%X\n", i);
  } else return;*/

  target_ulong mmap_first = DECAF_get_first_mmap(env, i);
  target_ulong mmap_i = mmap_first;
  target_ulong vmfile = 0;
  target_ulong flags = 0;
  target_ulong vmstart = 0;
  target_ulong vmend = 0;
  target_ulong startbrk = 0;
  target_ulong brk = 0;
  target_ulong startstack = 0;
  target_ulong mm = 0;
  target_ulong vm_pgoff = -1;
  //if (pid == 1004) printf("looking at the mmap at 0x%X\n", mmap_first);
  do
  {
    vmstart = DECAF_get_vm_start(env, mmap_i);
    vmend = DECAF_get_vm_end(env, mmap_i);
    flags = DECAF_get_vm_flags(env, mmap_i);
    mm = DECAF_get_mm(env, i);
    startbrk = DECAF_get_start_brk(env, mm);
    brk = DECAF_get_brk(env, mm);
    startstack = DECAF_get_start_stack(env, mm);

    //from mm.h
    //#define VM_READ         0x00000001      /* currently active flags */
    //#define VM_WRITE        0x00000002
    //#define VM_EXEC         0x00000004
    //#define VM_SHARED       0x00000008

    vmfile = DECAF_get_vm_file(env, mmap_i);
    //if (pid == 1004) printf("looking at vmfile at 0x%X\n", vmfile);
    //if (pid == 1004) printf(" ranging from 0x%X to 0x%X\n", vmstart, vmend);
    if (vmfile != 0)
    {
      //get_mod_dname(mmap_i, name, 128);
      DECAF_get_mod_full_dname(env, mmap_i, name, 128);

      /* Only valid when there is a file. This is in PAGE_SIZE units (4K) */
      vm_pgoff = DECAF_get_vm_pgoff(env, mmap_i) * 4 * 1024;
      //if (pid == 1004) printf("found dname %s @ offset 0x%X\n", name, vm_pgoff);
    }
    else
    {
      name[0] = '\0';
      //get_mod_iname(mmap_i, name, 128);
      DECAF_get_mod_full_iname(env, mmap_i, name, 128);
      if (strlen(name) <= 0)
      {
        if (vmstart <= startbrk && vmend >= brk)
        {
          sprintf(name, "[heap]");
        }
        else if (vmstart <= startstack && vmend >= startstack)
        {
          sprintf(name, "[stack]");
        }
      } else {
       //if (pid == 1004) printf("found iname %s\n", name);   
      }
    }

    updateModule(pid, vmstart, vmend, flags, name, vm_pgoff);
    mmap_i = DECAF_get_next_mmap(env, mmap_i);
  } while ((mmap_i != 0) && (mmap_i != mmap_first));

}

inline void update_mod(CPUState* env, gpid_t pid)
{
  updateProcessModuleList(env, pid);
}

inline void linux_print_mod(Monitor* mon, gpid_t pid)
{
  //We can pass in NULL since printModuleList uses DECAF_fprintf
  printModuleList(NULL, pid);
}


/**
 * @param val the current pgd-cr3 value
 *
 * The task list can be obtained in two ways.
 * 1. Using next_task_struct which uses the global symbol for init_task as the starting point
 * 2. Using the current_task_struct structure. This should just "work" although there are some
 *   special considerations in some special cases. current_task_struct returns the actual
 *   task struct - which can either be a process task struct or a thread task struct (if it
 *   is single threaded). Either way, it is guaranteed that the next pointer in task struct
 *   will either point to the next process task struct or init_task. Which means the loop
 *   should still work.
 *
 * Perhaps it is helpful to illustrate how the process/thread list really works
 * There are two fields in the task_struct that are of interest
 * 1. The next pointer that points to the next task struct
 * 2. The thread_group field (which is of type struct list_head { list_head* next, prev })
 *    This means task_struct.thred_group will automatically give you next. The tricky thing
 *    is that this list points to the thread_group field of the next task_struct that belongs
 *    to this group. See the figure below.
 * To put things together, lets assume that we have two running processes, 30 and 31.
 * 31 is single threaded and 30 is multi-threaded with two additional threads 32 and 33.
 * Given that we always have init_task, we should have a total of 5 task_structs, 1 for init
 *   2 for the processes and 2 for the threads.
 * The following is a graphical representation of the "process list"
 *
 * ,--------------------------------------------------------------------,
 * |     _____________          _____________          _____________    |
 * |---> | pid = 0   |    ,---> | pid = 30  |    ,---> | pid = 31  |    |
 * |     | tgid = 0  |    |     | tgid = 30 |    |     | tgid = 31 |    |
 * |     | next      | ---'     | next      | ---|     | next      | ---'
 * | ,-> | t-group   | -,   ,-> | t-group   | -, | ,-> | t-group   | --,
 * | |   |___________|  |  /    |___________|  | | |   |___________|   |
 * | '------------------' /                    | | '-------------------'
 * |                     / ,-------------------' |
 * |                    |  |    _____________    |
 * |                    |  |    | pid = 32  |    |
 * |                    |  |    | tgid = 30 |    |
 * |                    |  |    | next      | ---' (points to real next)
 * |                    |  '--> | t-group   | --,
 * |                    |       |___________|   |
 * |                    |  ,--------------------'
 * |                    |  |    _____________
 * |                    |  |    | pid = 33  |
 * |                    |  |    | tgid = 30 |
 * |                    |  |    | next      | ----, (points to init_task)
 * |                    |  '--> | t-group   | --, |
 * |                    |       |___________|   | |
 * |                    '-----------------------' |
 * '----------------------------------------------'
 *
 * Some things to emphasize (again?)
 * 1. thread_group.next (represented by t-group) points to the next thread_group field!
 * 2. next of the process task struct in the process list is guaranteed to point to the next
 *   task struct. The next in the thread task_struct might point to next or init_task
 * 3. According to online references, the pid's are always unique - this is why thread ids
 *   for the process 30 are 30 (the main thread) 32 and 33 (the other two threads).
 * 4. The tgid shows the real pid.
 *
 * The above example does not include the "thread_info" structure. Each task_struct
 *   is associated with its own thread_info structure which is pointed to by the "stack" field of the
 *   task_struct. To DECAF_get the stack address of the task - we will have to go into the thread info structure
 *   and look at the cpu_context field to grab the stack pointer. More info on the cpu_context and copy_thread
 *   (called from copy_process called from do_fork) can be found in arch/ARCH/kernel/process.c
 */
gva_t updateProcessListByTask(CPUState* env, gva_t task, int updateMask, int bNeedMark)
{
  gpid_t pid;
  gpid_t parentPid;
  gpid_t tgid;
  gpid_t glpid;
  target_ulong uid;
  target_ulong gid;
  target_ulong euid;
  target_ulong egid;

  gpid_t t_pid;
  gpid_t t_tgid;

  target_asid_t pgd;
  char name[MAX_PROCESS_INFO_NAME_LEN];
  char argName[MAX_PROCESS_INFO_NAME_LEN];
  gva_t i = task;

  argName[0] = '\0';
  name[0] = '\0';

  pid = DECAF_get_pid(env, i);
  tgid = DECAF_get_tgid(env, i);
  glpid = DECAF_get_group_leader_pid(env, i);
  uid = DECAF_get_uid(env, i);
  gid = DECAF_get_gid(env, i);
  euid = DECAF_get_euid(env, i);
  egid = DECAF_get_egid(env, i);
  parentPid = DECAF_get_parent_pid(env, i);
  pgd = pgd_strip(DECAF_get_pgd(env, i));

  //if (curProcessPGD == pgd)
  {
    if (DECAF_get_arg_name(env, i, argName, MAX_PROCESS_INFO_NAME_LEN) < 0)
    {
      argName[0] = '\0';
      //printf("failed to get argname\n");
    }
  }
  if (DECAF_get_name(env, i, name, MAX_PROCESS_INFO_NAME_LEN) < 0) //get the name
  {
    name[0] = '\0';
  }

  //update the info if needed
  if ( ((bNeedMark) && (processMark(pid) == 1))
       || ((!bNeedMark) && (findProcessByPID(pid) == NULL)) 
     ) // i.e. it doesn't exist
  {
    addProcess(i, pid, parentPid, tgid, glpid, uid, gid, euid, egid, pgd, (argName[0] == '\0') ? NULL : argName, (name[0] == '\0') ? NULL : name);
    processMark(pid);
    //force a module and thread update
    updateMask |= UPDATE_THREADS | UPDATE_MODULES;
  }
  else
  {
    updateProcess(i, pid, parentPid, tgid, glpid, uid, gid, euid, egid, pgd, (argName[0] == '\0') ? NULL : argName, (name[0] == '\0') ? NULL : name);
  }

  if (updateMask & UPDATE_THREADS)
  {
    //update (repopulate) the threads
    gva_t j = i;
    clearThreads(pid);
    do
    {
      if ((j != 0) && (j != -1))
      {
        t_pid = DECAF_get_pid(env, j);
        t_tgid = DECAF_get_tgid(env, j);

        //run through the thread group
        gva_t parentTI = DECAF_get_stack(env, j);
        addThread(t_tgid, t_pid, parentTI);
      }

      j = DECAF_get_thread_group(env, j);
      if ( (j == -1) || (j == 0) )
      {
        break;
      }
      j -= task_struct_thread_group_offset;//this gives you the next one immediately
    } while ( i != j );
  } //end bUpdateThreads

  //update (repopulate) the module list
  if (updateMask & UPDATE_MODULES)
  {
    updateProcessModuleList(env, pid);
  }

  i = DECAF_get_next_task_struct(env, i);
  return (i);
}

void updateProcessList(CPUState* env, target_asid_t newpgd, int updateMask)
{
  if (env == NULL)
  {
    return;
  }

  if (env->regs[15] < 0xC0000000)
  {
    return;
  }

  gva_t task = DECAF_get_current_process(env);

  if (task == 0)
  {
    return;
  }

  target_asid_t pgd;
  gpid_t pid;

  gva_t i = task;
  //begin the marking process
  //TODO: This is not thread safe - might lose some information
  processMarkBegin();
  do
  {
    pgd = pgd_strip(DECAF_get_pgd(env, i));
    pid = DECAF_get_pid(env,i);
    //see if this is the new process, if it is, then update the current PID
    if (pgd == pgd_strip(newpgd))
    {
      curProcessPID = pid;
      curProcessPGD = pgd;
    }
 
    i = updateProcessListByTask(env, i, updateMask, 1);
  } while ( (i != task) && ( i != 0) );

  gpid_t* pids = NULL;
  size_t len = 0;
  size_t j = 0;

  //mark the end as well as get an array of all the affected pids
  processMarkEnd(&pids, &len);

  if (len > 0)
  {
    free(pids);
  }

  return;
}

inline void get_symbol(CPUState* env, gpid_t pid, gva_t addr)
{
  char name[128];
  name[0] = '\0';
  getNearestSymbol(name, 128, pid, addr);
  DECAF_printf("%08x is in %s\n", addr, name);
}

inline void get_symbol_address(Monitor* mon, int pid, const char* strModule, const char* strName)
{
  DECAF_printf("%s is at [%x]\n", strName, getSymbolAddress(pid, strModule, strName));
}

inline void linux_ps(Monitor* mon)
{
  //We can pass in NULL since printProcessList uses DECAF_fprintf
  printProcessList(NULL);
}

inline void linux_pt(Monitor* mon)
{
  //We can pass in NULL since printThreadsList uses DECAF_fprintf
  printThreadsList(NULL);
}

#if (1)
//reg 0 is c2_base0 and 1 is c2_base1
int Context_PGDWriteCallback(CPUState *env, target_ulong oldval, target_ulong newval)
{
  //struct timeval t;
  //gettimeofday(&t, NULL);


  //TODO: Keep a record of what the current PGD is and the new PGD is
  // so that we don't do unnecessary updates - this applies to the
  // skipupdates flag that is set when system calls are made as well
  if (!bSkipNextPGDUpdate)
  {
    updateProcessList(env, newval, UPDATE_PROCESSES | UPDATE_THREADS | UPDATE_MODULES /* TODO: we might only update the modules when switching to a program of our interest */);
        //printf("%s is at [%x]\n", "fputs", getSymbolAddress(1, "/init", "free"));
  }

  //reset this flag
  bSkipNextPGDUpdate = 0;

  ProcessInfo* info = findProcessByPID(curProcessPID);
#if 0
  fprintf(stderr, "Task is now pid %i [%s] [%s]\n", (int)curProcessPID,
	  !info ? "[null info]" : !info->strName ? "[null str]" : info->strName,
	  !info ? "[null info]" : !info->strComm ? "[null str]" : info->strComm
 	);
#endif

  return 0;
}

static gva_t Context_retAddr = 0;
//LOK: My tests have shown that do_fork -> then update on a PGD write is a perfect choice. Should change the logic to do that.
// it seems to cover many more cases than do_fork and schedule()
//TODO: have to fix the potential problem where this is called twice before the return is processed
// in which case the process name will not be updated properly
int contextBBCallback(CPUState* env, TranslationBlock* tb)
{
  static gva_t taskAddr = INV_ADDR;
  static int updateMask = 0;
  gpid_t pid = -1;
  /*TranslationBlock* tb = NULL;
  CPUState* env = NULL;

  DEFENSIVE_CHECK0(params == NULL);

  env = params->bb.env;
  tb = params->bb.tb;*/
  
  if (NULL == tb)
  {
    return 0;
  }

  if ( (tb->pc == SET_TASK_COMM_ADDR) || (tb->pc == DO_PRCTL_ADDR) )//set_task_comm
  {
    //In this case, we just update the name when the function returns
    //TODO: Fix i386 support 
    //TODO: Make sure this taskAddr is NOT the thread's task 
#ifdef TARGET_ARM
    taskAddr = env->regs[0];
    Context_retAddr = env->regs[14];
#elif defined(TARGET_I386)
    taskAddr = env->regs[R_EAX];
    DECAF_read_mem(env, env->regs[R_ESP], &Context_retAddr, sizeof(Context_retAddr));
#endif
  }
  else if ( (tb->pc == DO_EXECVE_ADDR) || (tb->pc == DO_CLONE_ADDR) )//do_execve
  {
    //we OR the update mask since its possible for the system call
    // to call another test - e.g. do_fork - and without declaring
    // the updateMask as static and using |= the flags will be
    // overwritten
    //TODO: Implement a STACK for the return addresses!!!
    //in this case we update the process, threads and module lists
    updateMask |= UPDATE_PROCESSES | UPDATE_THREADS | UPDATE_MODULES;
#ifdef TARGET_ARM
    Context_retAddr = env->regs[14];
#endif
  }
  else if (tb->pc == DO_FORK_ADDR) //do_fork
  {
    //In this case we just update the process and threads lists 
    updateMask |= UPDATE_PROCESSES | UPDATE_THREADS;
#ifdef TARGET_ARM
    Context_retAddr = env->regs[14];
#endif
  }

  if (tb->pc == Context_retAddr)
  {
    if (taskAddr != INV_ADDR)
    //if we need to update the names only
    {
      pid = DECAF_get_pid(env, taskAddr);
      if (pid != -1)
      {
        //if we found the PID then just read the names and update
        updateProcessListByTask(env, taskAddr, UPDATE_PROCESSES | UPDATE_THREADS | UPDATE_MODULES, 0);
      }
      taskAddr = INV_ADDR;
    } 
    else
    {
      updateProcessList(env, getCurrentPGD(), updateMask);
    }
    //since we updated the list already - lets skip the next PGD
    //write update
    bSkipNextPGDUpdate = 1;
    Context_retAddr = 0;
    //DECAF_flushTranslationBlock_env(env, Context_retAddr);
    //printProcessList(NULL);
    FILE* foo = fopen("/dev/null","w");
    //printModuleList(foo, 31);
    //printProcessList(NULL);
    printf("%s is at [%x]\n", "fputs", getSymbolAddress(341, "/lib/libdvm.so", "dvmAsmInstructionStart"));
    fclose(foo);
  }

  if (Context_retAddr != 0)
  {
    //instead of registering for a new callback - we will just update our
    //conditions list and flush the entry for retAddr
   //DECAF_flushTranslationBlock_env(env, Context_retAddr);
  }
    
  return 0;
}

#endif

#if defined(TARGET_ARM)
#define CURRENT_PGD(x) (x->cp15.c2_base0 & x->cp15.c2_base_mask)
#elif defined(TARGET_I386)
#define CURRENT_PGD(x) (x->cr[3])
#endif

static int return_from_exec(CPUState *env){
    updateProcessList(env, CURRENT_PGD(env), UPDATE_MODULES | UPDATE_PROCESSES | UPDATE_THREADS);
    fprintf(stderr, "from_exec\n");
    printProcessList(NULL);
    return 0;
}

static int return_from_fork(CPUState *env){
    updateProcessList(env, CURRENT_PGD(env), UPDATE_PROCESSES | UPDATE_THREADS);
    fprintf(stderr, "from_fork\n");
    printProcessList(NULL);
    return 0;
}
static int return_from_clone(CPUState *env){
    updateProcessList(env, CURRENT_PGD(env), UPDATE_PROCESSES | UPDATE_THREADS);
    fprintf(stderr, "from_clone\n");
    printProcessList(NULL);
    return 0;
}

bool bart_insn_translate(CPUState *env, target_ulong pc) {
#if 0
  ProcessInfo* info = findProcessByPID(curProcessPID);
  if (!info || !info->strComm)
    return false;

  if (strcmp("challenge3", info->strComm) == 0 || strcmp("sh", info->strComm) == 0 || strcmp("demo", info->strComm) == 0)
    return true;
  return false;
#endif
  return true;
}

target_offset_t getFileOffset(target_addr_t pc) {
  target_ulong startAddr, endAddr, vm_pgoff;
  char modulename[255];
  int res = getModuleInfoEx(curProcessPID, modulename, 255, &startAddr, &endAddr, pc, &vm_pgoff, NULL);
  if (res != 0)
    return -1;
  return pc - startAddr + vm_pgoff;
}

static const char* programName = nullptr;

target_offset_t offsetOfFirstInstruction = 0x0;

/* TODO: cache ProcessInfo probably */
bool shouldTrace(target_addr_t pc) {
  if (pc >= (target_addr_t) 0xc0000000)
    return false;

  ProcessInfo* info = findProcessByPID(curProcessPID);
  if (!info || !info->strComm)
    return false;

  if (!programName || (strcmp(programName, info->strComm) != 0))
    return false;

  gva_t startAddr, endAddr;
  char modulename[255];
  memset(modulename, 0, 255);

  int res = getModuleInfo(curProcessPID, modulename, 255, &startAddr, &endAddr, pc);
  if (res == 0 && ( strcmp("/lib/libc.so", modulename) == 0 || strcmp("/bin/linker", modulename) == 0 ) ){
    return false;
  }

  return true;
}

target_offset_t gmrt_offset = -1;
target_offset_t gmrt_size = 0;

bool isInMobileBlock(CPUState *env, MobileCodeInfo & info, target_addr_t pc)
{
  if (gmrt_offset == -1)
    return false;

  gva_t startAddr, endAddr;
  char modulename[255];
  memset(modulename, 0, 255);
  target_ulong flags;

  if (getModuleInfoByName(curProcessPID, &startAddr, &endAddr, libraryName) != 0 /* dumb API returns 0 on success */) {
    return false;
  }

  /* Currently, the GMRT is an array of the following:
     {
       t_address addr;          :: offset 0
       t_address downloaded;    :: offset 4
       pthread_mutex_t mutex;   :: offset 8
       size_t len;              :: offset 12
     } MobileEntry;             == size 16
  */
  static const target_offset_t GMRT_ENRTY_SIZE = 16;

  target_addr_t gmrt = gmrt_offset + startAddr;

  for (int idx = 0; idx < gmrt_size / GMRT_ENRTY_SIZE; idx++) {

    uint32_t buf[GMRT_ENRTY_SIZE/4];
    panda_virtual_memory_rw(env, gmrt + GMRT_ENRTY_SIZE * idx, (uint8_t*)buf, GMRT_ENRTY_SIZE, 0);

    /* The -8 is because Bert lets the downloaded pointer point to the first actual instruction of the block itself, while in the entire mobile blob
     * there are two instructions of 4 bytes each before it: a DATA instruction (this doesn't get executed so it doesn't matter in the start check),
     * and a POP instruction (this can be executed). These show up in the list file. Furthermore, the length is relative to the start of the mobile blob  */
    gva_t mapping_start = buf[0] - 8;

    if (pc >= mapping_start && pc < mapping_start + buf[3]) {
      info.blockId = idx;
      info.offsetInBlock = pc - mapping_start;

#if 0
	fprintf(stderr, "Currently in '%s' @ " TARGET_FMT_lx "\n", modulename, pc);
	fprintf(stderr, "GMRT[0].addr = 0x" TARGET_FMT_lx "\n", buf[0]);
	fprintf(stderr, "GMRT[0].downloaded = 0x" TARGET_FMT_lx "\n", buf[1]);
	fprintf(stderr, "GMRT[0].len = 0x" TARGET_FMT_lx "\n", buf[3]);
#endif

      return true;
    }
  }

  return false;
}

ProtectedProgramLocation getLocationFor(CPUState *env, target_addr_t pc, bool isPLTValid) {
  ProtectedProgramLocation location;

  gva_t startAddr, endAddr;
  char modulename[255];
  memset(modulename, 0, 255);
  target_ulong flags;
  int res = getModuleInfoEx(curProcessPID, modulename, 255, &startAddr, &endAddr, pc, NULL, &flags);

  if (strcmp(modulename, libraryName) != 0) {
    /* We're not in the protected library, but we might be in mobile code of it */
    if (isInMobileBlock(env, location.mobile, pc)) {
      location.valid = true;
      location.isMobile = true;
    } else {
      location.valid = false;
    }
  } else {
    location.valid = true;
    location.isMobile = false;
    location.libraryOffset = getFileOffset(pc);

    /* The PLT is located in the instructions before the first instruction in Diablo's list file */
    if (location.libraryOffset <= offsetOfFirstInstruction && !isPLTValid) {
      location.valid = false;
    }
  }

  return location;
}

int exec_bart_callback(CPUState *env, target_ulong pc) {
  /*if ((unsigned long)pc >= (unsigned long)0xc000000)
    return 0;*/

  // fprintf(trace_pc, TARGET_FMT_lx ":\n", pc);
  if (!shouldTrace(pc))
    return 0;

  ProcessInfo* info = findProcessByPID(curProcessPID);

  gva_t startAddr, endAddr, vm_pgoff;
  char modulename[255];
  memset(modulename, 0, 255);

  int res = getModuleInfoEx(curProcessPID, modulename, 255, &startAddr, &endAddr, pc, &vm_pgoff, NULL);

#if 0
  fprintf(trace_pc, TARGET_FMT_lx " @ %s, offset in file = 0x" TARGET_FMT_lx "\n", pc, res == 0 ? modulename : "[none]",  pc - startAddr + vm_pgoff);

  auto it = breakpoints.find(std::make_pair(pc, curProcessPID)); /* TODO: won't trigger return point of execve/fork?! */
  if (it != breakpoints.end()) {
    fprintf(trace_pc, "[%i] [%s] - ", (int)curProcessPID, !info ? "[null info]" : !info->strComm ? "[null str]" : info->strComm);
    fprintf(trace_pc, TARGET_FMT_lx ": ... ", /*tb->pc - 4*/pc);
    (*it).second(env, pc);
    breakpoints.erase(it);
    return 0;
  }
  if (is_syscall(env, /*tb->pc*/pc + 4)) {
    fprintf(trace_pc, " ('%s' 0x" TARGET_FMT_lx " - 0x" TARGET_FMT_lx " = %i ", modulename, startAddr, endAddr);
    dump_syscall(env, pc, info);
  }
#endif

  fflush(trace_file);

  return 0;
}

int backward_trace_len = 0;
int forward_trace_len = 0;

const char* libraryName = nullptr;

FILE* trace_file = nullptr;
FILE* reuse_file = nullptr;
FILE* memory_file = nullptr;
FILE* entropy_file = nullptr;

int bart_init()
{
  /* Format is linux_vmi:opt1=<val1>,etc
     trace_file=<file>
     reuse_file=<file>
     memory_file=<file>
     gmrt_offset=<hexint>
     gmrt_size=<hexint>
     library_name=<file>
     traced_program=<file>
     trace_memory_reuse=<0|1> # default: 0
     trace_memory_constness=<0|1> # default: 0
     offset_of_first_instruction=<hexint>

     Example: linux_vmi:gmrt_offset=0x3ac0b8,gmrt_size=0x10,traced_program=demo,library_name=/liblib.so,trace_memory_reuse=1,trace_memory_constness=1,offset_of_first_instruction=0x0,backward_trace_len=1,forward_trace_len=0
     */

    const char* filename_trace = "trace_pc";
    const char* filename_reuse = "memory_reuse_distance";
    const char* filename_memory = "memory_constness";
    const char* filename_entropy = "trace_entropy";

    int trace_memory_reuse = 0;
    int trace_memory_constness = 0;
    int trace_entropy = 1;

    panda_arg_list *args = panda_get_args("linux_vmi");

    if (args != NULL) {
      for (int i = 0; i < args->nargs; i++) {
	if (strcmp(args->list[i].key, "gmrt_offset") == 0) {
	  gmrt_offset = strtol(args->list[i].value, NULL, 0);
	} else if (strcmp(args->list[i].key, "gmrt_size") == 0) {
	  gmrt_size = strtol(args->list[i].value, NULL, 0);
	} else if (strcmp(args->list[i].key, "library_name") == 0) {
	  libraryName = args->list[i].value;
	} else if (strcmp(args->list[i].key, "traced_program") == 0) {
	  programName = args->list[i].value;
	} else if (strcmp(args->list[i].key, "reuse_file") == 0) {
	  filename_reuse = args->list[i].value;
	} else if (strcmp(args->list[i].key, "memory_file") == 0) {
	  filename_reuse = args->list[i].value;
	} else if (strcmp(args->list[i].key, "trace_file") == 0) {
	  filename_trace = args->list[i].value;
	} else if (strcmp(args->list[i].key, "trace_memory_constness") == 0) {
	  trace_memory_constness = atoi(args->list[i].value);
	} else if (strcmp(args->list[i].key, "trace_memory_reuse") == 0) {
	  trace_memory_reuse = atoi(args->list[i].value);
	} else if (strcmp(args->list[i].key, "offset_of_first_instruction") == 0) {
	  offsetOfFirstInstruction = strtol(args->list[i].value, NULL, 0);
	} else if (strcmp(args->list[i].key, "backward_trace_len") == 0) {
	  backward_trace_len = atoi(args->list[i].value);
	} else if (strcmp(args->list[i].key, "forward_trace_len") == 0) {
	  forward_trace_len = atoi(args->list[i].value);
	}
      }
    }

    trace_file = fopen(filename_trace , "w");
    reuse_file = fopen(filename_reuse, "w");
    memory_file = fopen(filename_memory, "w");
    entropy_file = fopen(filename_entropy, "w");

    // Need this to get EIP with our callbacks
    panda_enable_precise_pc();

    // Enable memory logging
    panda_enable_memcb();

    panda_cb callback;

    callback.insn_translate = bart_insn_translate;
    panda_register_callback(NULL, PANDA_CB_INSN_TRANSLATE, callback);

    callback.insn_exec = exec_bart_callback;
    panda_register_callback(NULL, PANDA_CB_INSN_EXEC, callback);

    if (trace_memory_constness) {
      panda_cb callback_memory;

      callback_memory.virt_mem_write = mem_write_callback_constness;
      panda_register_callback(NULL, PANDA_CB_VIRT_MEM_WRITE, callback_memory);
    }

    if (trace_memory_reuse) {
      panda_cb callback_memory;

      callback_memory.virt_mem_write = mem_write_callback_reuse;
      panda_register_callback(NULL, PANDA_CB_VIRT_MEM_WRITE, callback_memory);

      callback_memory.virt_mem_read = mem_read_callback_reuse;
      panda_register_callback(NULL, PANDA_CB_VIRT_MEM_READ, callback_memory);
    }

    if (trace_entropy) {
      panda_cb callback_entropy;
      callback_entropy.after_block_exec = after_block_exec_trace_entropy;
      panda_register_callback(NULL, PANDA_CB_AFTER_BLOCK_EXEC, callback_entropy);

      callback_entropy.before_block_exec = before_block_exec_trace_entropy;
      panda_register_callback(NULL, PANDA_CB_BEFORE_BLOCK_EXEC, callback_entropy);
    }

    return 0;
}

void bart_close()
{
  dump_write_constness();
  dump_write_reuse();
  dump_write_entropy_trace();


  fclose(trace_file);
  fclose(memory_file);
  fclose(reuse_file);
  fclose(entropy_file);
}

#if (1)
extern "C" void context_init(void)
{

  panda_cb callback;
  callback.return_from_fork = return_from_fork;
  panda_register_callback(NULL, PANDA_CB_VMI_AFTER_FORK, callback);
  callback.return_from_exec = return_from_exec;
  panda_register_callback(NULL, PANDA_CB_VMI_AFTER_EXEC, callback);
  callback.return_from_clone = return_from_clone;
  panda_register_callback(NULL, PANDA_CB_VMI_AFTER_CLONE, callback);
  callback.after_PGD_write = Context_PGDWriteCallback;
  panda_register_callback(NULL, PANDA_CB_VMI_PGD_CHANGED, callback);

  bart_init();
}

extern "C" void context_close(void)
{
  bart_close();
}
#endif
