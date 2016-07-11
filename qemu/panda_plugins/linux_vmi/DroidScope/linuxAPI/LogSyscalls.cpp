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

bool is_syscall(CPUState* env, target_ulong end_addr) {
  uint8_t buf[4];
  if(/*env->thumb == 0*/ 1 ) {
    panda_virtual_memory_rw(env, end_addr - 4, buf, 4, 0);
    if ( ((buf[3] & 0x0F) ==  0x0F)  && (buf[2] == 0) && (buf[1] == 0) && (buf[0] == 0) ) {
      //fprintf(trace_file, TARGET_FMT_lx " - %hhx %hhx %hhx %hhx\n", end_addr - 4, buf[3], buf[2], buf[1], buf[0]);

      return true; 
    } else {
      /*if (buf[1] == 0xDF && buf[0] == 0){
	return true;
      }*/
    }
    //return true;
  }
  return false;
}

static std::map< std::pair<uint32_t, gpid_t>, std::function<void (CPUState*, target_ulong)>> breakpoints;

void dump_sized_asciibuf(CPUState* env, uint32_t ptr, uint32_t max) {
  uint8_t buf;
  while (panda_virtual_memory_rw(env, ptr, &buf, 1, 0 /* is_write */), buf != 0 && ( (buf >= ' ' && buf <= '}') || buf == '\n') && ptr < max) {
    fprintf(trace_file,"%c", buf);
    ptr++;
  }
}

void printstring(CPUState* env, uint32_t ptr) {
  unsigned char buf;
  while (panda_virtual_memory_rw(env, ptr++, &buf, 1, 0 /* is_write */), buf != 0) {
	  fprintf(trace_file,"%c", buf);
  }
}

void dump_syscall(CPUState *env, target_ulong pc, ProcessInfo* info) {
    fprintf(trace_file, "[%i] [%s] - ", (int)curProcessPID, !info ? "[null info]" : !info->strComm ? "[null str]" : info->strComm);
    fprintf(trace_file, TARGET_FMT_lx ": ", /*tb->pc - 4*/pc);

    //char c;
    //panda_virtual_memory_rw(env, tb->pc - 8, &c, 1, 0);
    
#define SYSCALL_NOARGS(id, name) \
    case id: { \
      fprintf(trace_file, #name "()\n"); \
    } \
    break /* no ; so I can put a nice ; after the macro instantiation */

#define SYSCALL_INTARG(id, name, argnr) \
    case id: { \
      fprintf(trace_file, #name "(%i)\n", env->regs[argnr]); \
    } \
    break /* no ; so I can put a nice ; after the macro instantiation */

#define SYSCALL_INTARG_NAMED(id, name, argname, argnr) \
    case id: { \
      fprintf(trace_file, #name "(" argname "=%i)\n", env->regs[argnr]); \
    } \
    break /* no ; so I can put a nice ; after the macro instantiation */

#define SYSCALL_STRINGARG_NAMED(id, name, argname, argnr) \
    case id: { \
      fprintf(trace_file, #name "(" argname "='"); \
      printstring(env, env->regs[argnr]); \
      fprintf(trace_file,"')\n"); \
    } \
    break /* no ; so I can put a nice ; after the macro instantiation */


    switch(env->regs[7]) {
      // 1 long sys_exit ['int error_code']
      SYSCALL_INTARG(1, sys_exit, 0);
      // sys_fork
      SYSCALL_NOARGS(2, fork);
      case 3:
      {
	// 3 long sys_read ['unsigned int fd', ' char __user *buf', ' size_t count']
	uint32_t buf_ptr = env->regs[1];
	int size = env->regs[2];
	fprintf(trace_file,"sys_read(fd=%i, count=%i)\n", env->regs[0], size);
	breakpoints[std::make_pair(pc+4, curProcessPID)] = [buf_ptr](CPUState* env, target_ulong pc) { 
	  fprintf(trace_file, "... sys_read = %i", env->regs[0]);
	  if ( ((int)env->regs[0]) > 0) {
	    fprintf(trace_file, ", buf='");
	    dump_sized_asciibuf(env,  buf_ptr, buf_ptr + env->regs[0]);
	    fprintf(trace_file, "'\n");
	  } else {
	    fprintf(trace_file, "\n");
	  }
	};
      }
      break;
      // 6 long sys_close ['unsigned int fd']
      SYSCALL_INTARG_NAMED(6, sys_close, "fd", 0);
      case 11:
      {
	unsigned char buf;
	uint32_t ptr = env->regs[0];
	fprintf(trace_file,"sys_execve('");
	while (panda_virtual_memory_rw(env, ptr++, &buf, 1, 0 /* is_write */), buf != 0) {
	  fprintf(trace_file,"%c", buf);
	}
	fprintf(trace_file,"')\n");
      }
      break;
      case 4:
      {
	// 4 sys_write ['unsigned int fd', ' const char __user *buf', 'size_t count']
	unsigned char buf;
	fprintf(trace_file,"sys_write(%i, '", (int) env->regs[0]);
	dump_sized_asciibuf(env, env->regs[1], env->regs[1] + env->regs[2]);
	
	fprintf(trace_file,"', %i", (int) env->regs[2]);
	fprintf(trace_file,"')\n");
      }
      break;
      case 5:
      {
	unsigned char buf;
	uint32_t ptr = env->regs[0];
	fprintf(trace_file,"sys_open('");
	printstring(env, ptr);
	fprintf(trace_file,"') = ...\n");
	breakpoints[std::make_pair(pc+4, curProcessPID)] = [](CPUState* env, target_ulong pc) { fprintf(trace_file, " =  %i\n", env->regs[0]); };
      }
      break;
      // 10 long sys_unlink ['const char __user *pathname']
      SYSCALL_STRINGARG_NAMED(10, sys_unlink, "pathname", 0);
      // 19 long sys_lseek ['unsigned int fd', ' off_t offset', 'unsigned int origin']
      SYSCALL_INTARG_NAMED(19, sys_lseek, "fd", 0);
      // 20 long sys_getpid ['void']
      SYSCALL_NOARGS(20, sys_getpid);
      case 38: {
	// 38 long sys_rename ['const char __user *oldname', 'const char __user *newname']
	fprintf(trace_file,"sys_rename(oldname='");
	printstring(env, env->regs[0]);
	fprintf(trace_file,"', newname='");
	printstring(env, env->regs[1]);
	fprintf(trace_file,"')\n");
	break;
      }
      // 39 long sys_mkdir ['const char __user *pathname', ' int mode']
      SYSCALL_STRINGARG_NAMED(39, sys_mkdir, "pathname", 0);
      // 42 long sys_pipe ['int __user *']
      SYSCALL_NOARGS(42, sys_pipe);
      // 45 sys_brk ['unsigned long brk']
      SYSCALL_INTARG(45, sys_brk, 0);
      // 54 long sys_ioctl ['unsigned int fd', ' unsigned int cmd', 'unsigned long arg']
      SYSCALL_INTARG_NAMED(54, sys_ioctl, "fd", 0);
      // 64 long sys_getppid ['void']
      SYSCALL_NOARGS(64, sys_getppid);
      // 67 int sigaction ['int sig', ' const struct old_sigaction __user *act', ' struct old_sigaction __user *oact']
      SYSCALL_INTARG_NAMED(67, sigaction, "sig", 0);
      // 72 long sigsuspend ['int restart', ' unsigned long oldmask', ' old_sigset_t mask']
      SYSCALL_NOARGS(72, sigsuspend);
      // 77 long sys_getrusage ['int who', ' struct rusage __user *ru']
      SYSCALL_NOARGS(77, sys_getrusage);
      // 78 long sys_gettimeofday ['struct timeval __user *tv', 'struct timezone __user *tz']
      SYSCALL_NOARGS(78, sys_gettimeofday);
      case 91:
      {
	// 91 long sys_munmap ['unsigned long addr', ' size_t len']
	fprintf(trace_file,"sys_munmap(0x%x, len=%u)\n", (int) env->regs[0], (int) env->regs[1]);
      }
      break;
      // 104 long sys_setitimer ['int which', 'struct itimerval __user *value', 'struct itimerval __user *ovalue']
      SYSCALL_NOARGS(104, sys_setitimer);
      case 114:
      {
	// 114 long sys_wait4 ['pid_t pid', ' int __user *stat_addr', 'int options', ' struct rusage __user *ru']
	fprintf(trace_file,"sys_wait4(%u)\n", (int) env->regs[0]);
      }
      break;
      case 120:
      {
	// 120 unsigned long clone ['unsigned long clone_flags', ' unsigned long newsp', ' int __user *parent_tidptr', ' int tls_val', ' int __user *child_tidptr', ' struct pt_regs *regs']
	fprintf(trace_file,"sys_clone(flags=0x%x, ...)\n", (int) env->regs[0]);
      }
      break;
      case 125:
      {
	// 125 long sys_mprotect ['unsigned long start', ' size_t len', 'unsigned long prot']
	fprintf(trace_file,"sys_mprotect(0x%x, len=%u, prot=%x (%s|%s|%s|%s])\n", (int) env->regs[0], (int) env->regs[1], (int) env->regs[2],
	  (env->regs[2] & PROT_NONE) ? "PROT_NONE" : "",
	  (env->regs[2] & PROT_READ) ? "PROT_READ" : "",
	  (env->regs[2] & PROT_WRITE) ? "PROT_WRITE" : "",
	  (env->regs[2] & PROT_EXEC) ? "PROT_EXEC" : "");
      }
      break;
      // 126 long sys_sigprocmask ['int how', ' old_sigset_t __user *set', 'old_sigset_t __user *oset']
      SYSCALL_NOARGS(126, sys_poll);
      // 132 long sys_getpgid ['pid_t pid']
      SYSCALL_INTARG_NAMED(132, sys_getpgid, "pid", 0);
      // 168 long sys_poll ['struct pollfd __user *ufds', ' unsigned int nfds', 'long timeout']
      SYSCALL_NOARGS(168, sys_poll);
      // 183 long sys_getcwd ['char __user *buf', ' unsigned long size']
      SYSCALL_NOARGS(183, sys_getcwd);
      // 191 long sys_getrlimit ['unsigned int resource', 'struct rlimit __user *rlim']
      SYSCALL_NOARGS(191, sys_getrlimit);
      case 192:
      {
	// 192 long do_mmap2 ['unsigned long addr', ' unsigned long len', ' unsigned long prot', ' unsigned long flags', ' unsigned long fd', ' unsigned long pgoff']
	fprintf(trace_file,"do_mmap2(0x%x, %u, fd=%i, pgoff=%i, prot=%x [%s|%s|%s|%s])\n", (int) env->regs[0], (int) env->regs[1], (int) env->regs[4], (int) env->regs[5], (int) env->regs[2],
  	  (env->regs[2] & PROT_NONE) ? "PROT_NONE" : "",
	  (env->regs[2] & PROT_READ) ? "PROT_READ" : "",
	  (env->regs[2] & PROT_WRITE) ? "PROT_WRITE" : "",
	  (env->regs[2] & PROT_EXEC) ? "PROT_EXEC" : "");
      }
      break;
      case 195:
      {
	// 195 long sys_stat64 ['char __user *filename', 'struct stat64 __user *statbuf']
	fprintf(trace_file,"sys_stat64(filename='");
	printstring(env, env->regs[0]);
	fprintf(trace_file,"')\n");
      }
      break;
      // 197 long sys_fstat64 ['unsigned long fd', ' struct stat64 __user *statbuf']
      SYSCALL_INTARG_NAMED(197, sys_fstat64, "fd", 0);
      // 199 long sys_getuid ['void']
      SYSCALL_NOARGS(199, sys_getuid);
      // 200 long sys_getgid ['void']
      SYSCALL_NOARGS(200, sys_getgid);
      // 201 long sys_geteuid ['void']
      SYSCALL_NOARGS(201, sys_geteuid);
      // 202 long sys_getegid ['void']
      SYSCALL_NOARGS(202, sys_getegid);
      case 220:
      {
	// 220 long sys_madvise ['unsigned long start', ' size_t len', ' int behavior']
	fprintf(trace_file,"sys_madvise(0x%x, len=%u, behavior=%x)\n", (int) env->regs[0], (int) env->regs[1], (int) env->regs[2]);
      }
      break;
      // 221 long sys_fcntl64 ['unsigned int fd', 'unsigned int cmd', ' unsigned long arg']
      SYSCALL_INTARG_NAMED(221, sys_fcntl64, "fd", 0);
      // 224 long sys_gettid ['void']
      SYSCALL_NOARGS(224, sys_gettid);
      // 240 long sys_futex ['u32 __user *uaddr', ' int op', ' u32 val', 'struct timespec __user *utime', ' u32 __user *uaddr2', 'u32 val3']
      SYSCALL_NOARGS(240, sys_futex);
      // 248 long sys_exit_group ['int error_code']
      SYSCALL_INTARG(248, sys_exit_group, 0);
      // 263 long sys_clock_gettime ['clockid_t which_clock', 'struct timespec __user *tp']
      SYSCALL_NOARGS(263, sys_clock_gettime);
      // 281 long sys_socket ['int', ' int', ' int']
      case 281:
      {
	unsigned char buf;
	uint32_t ptr = env->regs[0];
	fprintf(trace_file,"sys_socket(...) = ...\n");
	breakpoints[std::make_pair(pc+4, curProcessPID)] = [](CPUState* env, target_ulong pc) { fprintf(trace_file, " =  %i\n", env->regs[0]); };
      }
      break;
      // 283 long sys_connect ['int', ' struct sockaddr __user *', ' int']
      SYSCALL_INTARG_NAMED(283, sys_connect, "fd", 0);
      // 290 long sys_sendto ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int']
      SYSCALL_INTARG_NAMED(290, sys_sendto, "fd", 0);
      // 286 long sys_getsockname ['int', ' struct sockaddr __user *', ' int __user *']
      SYSCALL_INTARG_NAMED(286, sys_getsockname, "fd", 0);
      // 287 long sys_getpeername ['int', ' struct sockaddr __user *', ' int __user *']
      SYSCALL_INTARG_NAMED(287, sys_getpeername, "fd", 0);
      // 292 long sys_recvfrom ['int', ' void __user *', ' size_t', ' unsigned', 'struct sockaddr __user *', ' int __user *']
      SYSCALL_INTARG_NAMED(292, sys_recvfrom, "fd", 0);
      // 293 long sys_shutdown ['int', ' int']
      SYSCALL_NOARGS(293, sys_shutdown);
      // 294 long sys_setsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int optlen']
      SYSCALL_INTARG_NAMED(294, sys_setsockopt, "fd", 0);
      // 295 long sys_getsockopt ['int fd', ' int level', ' int optname', 'char __user *optval', ' int __user *optlen']
      SYSCALL_INTARG_NAMED(295, sys_getsockopt, "fd", 0);
      default:
	//fprintf(trace_file, "sys_%i_%i\n", (unsigned int)(env->regs[7] & 0xff), (unsigned int)(c));
	fprintf(trace_file, "sys_%i\n", (unsigned int)(env->regs[7]));
    }
}

