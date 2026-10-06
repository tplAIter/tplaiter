/* Neutral pre-installation feasibility entry only. No executor or permit API. */
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <mach/mach.h>
static int bound(int resource, rlim_t ceiling, const char *label) {
 struct rlimit old, actual;
 if (getrlimit(resource, &old)) return 10;
 rlim_t n=old.rlim_cur < ceiling ? old.rlim_cur : ceiling;
 if (old.rlim_max < n) n=old.rlim_max;
 struct rlimit wanted={n,n};
 if (setrlimit(resource,&wanted)) {
  dprintf(2,"LIMIT_REFUSAL %s errno=%d requested=%llu\n",label,errno,(unsigned long long)n); return 11;
 }
 if (getrlimit(resource,&actual) || actual.rlim_cur!=n || actual.rlim_max!=n) return 12;
 dprintf(2,"LIMIT_SET %s soft=%llu hard=%llu\n",label,(unsigned long long)n,(unsigned long long)n);
 return 0;
}
int main(int argc, char **argv) {
 (void)argv;
 mach_task_basic_info_data_t info;
 mach_msg_type_number_t count=MACH_TASK_BASIC_INFO_COUNT;
 kern_return_t kr=task_info(mach_task_self(),MACH_TASK_BASIC_INFO,(task_info_t)&info,&count);
 if(kr!=KERN_SUCCESS || count!=MACH_TASK_BASIC_INFO_COUNT) return 20;
 uint64_t baseline=(uint64_t)info.virtual_size;
 dprintf(2,"NEUTRAL_BASELINE bytes=%llu\n",(unsigned long long)baseline);
 if(baseline>((uint64_t)32<<30)) {dprintf(2,"BASELINE_CAP_REFUSAL max=34359738368\n");return 21;}
#ifndef EXPECTED_BASELINE
 dprintf(2,"BASELINE_ONLY_NO_LIMIT_OR_ACTION_CLAIM\n");return 0;
#else
 if(baseline!=(uint64_t)EXPECTED_BASELINE) return 22;
#endif
 dprintf(2,"FEASIBILITY_ENTRY\n");
 if (argc!=1) return 2;
 int r;
 if ((r=bound(RLIMIT_AS,baseline+(((rlim_t)2)<<30),"AS"))) return r;
 if ((r=bound(RLIMIT_CPU,5,"CPU"))) return r;
 if ((r=bound(RLIMIT_STACK,((rlim_t)8)<<20,"STACK"))) return r;
 if ((r=bound(RLIMIT_NOFILE,256,"NOFILE"))) return r;
 if ((r=bound(RLIMIT_CORE,0,"CORE"))) return r;
 if ((r=bound(RLIMIT_FSIZE,0,"FSIZE"))) return r;
 errno=0;
 void *v=mmap(NULL,(size_t)(baseline+((uint64_t)3<<30)),PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(v!=MAP_FAILED) {munmap(v,(size_t)(baseline+((uint64_t)3<<30))); dprintf(2,"ALLOCATION_UNEXPECTEDLY_ALLOWED\n");return 13;}
 dprintf(2,"ALLOCATION_REFUSED errno=%d\n",errno);
 if(errno!=ENOMEM) return 14;
 dprintf(2,"FEASIBILITY_PASS_NOT_INSTALLED_NOT_ACTION_AUTHORITY\n");
 return 0;
}
