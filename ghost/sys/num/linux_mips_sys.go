package num

var Linux_mips = map[int]string{
	4000: "syscall",
	4001: "exit",
	4002: "fork",
	4003: "read",
	4004: "write",
	4005: "open",
	4006: "close",
	4007: "waitpid",
	4008: "creat",
	4009: "link",
	4010: "unlink",
	4011: "execve",
	4012: "chdir",
	4013: "time",
	4014: "mknod",
	4015: "chmod",
	4016: "lchown",
	4017: "break",
	4018: "unused18",
	4019: "lseek",
	4020: "getpid",
	4021: "mount",
	4022: "umount",
	4023: "setuid",
	4024: "getuid",
	4025: "stime",
	4026: "ptrace",
	4027: "alarm",
	4028: "unused28",
	4029: "pause",
	4030: "utime",
	4031: "stty",
	4032: "gtty",
	4033: "access",
	4034: "nice",
	4035: "ftime",
	4036: "sync",
	4037: "kill",
	4038: "rename",
	4039: "mkdir",
	4040: "rmdir",
	4041: "dup",
	4042: "pipe",
	4043: "times",
	4044: "prof",
	4045: "brk",
	4046: "setgid",
	4047: "getgid",
	4048: "signal",
	4049: "geteuid",
	4050: "getegid",
	4051: "acct",
	4052: "umount2",
	4053: "lock",
	4054: "ioctl",
	4055: "fcntl",
	4056: "mpx",
	4057: "setpgid",
	4058: "ulimit",
	4059: "unused59",
	4060: "umask",
	4061: "chroot",
	4062: "ustat",
	4063: "dup2",
	4064: "getppid",
	4065: "getpgrp",
	4066: "setsid",
	4067: "sigaction",
	4068: "sgetmask",
	4069: "ssetmask",
	4070: "setreuid",
	4071: "setregid",
	4072: "sigsuspend",
	4073: "sigpending",
	4074: "sethostname",
	4075: "setrlimit",
	4076: "getrlimit",
	4077: "getrusage",
	4078: "gettimeofday",
	4079: "settimeofday",
	4080: "getgroups",
	4081: "setgroups",
	4082: "reserved82",
	4083: "symlink",
	4084: "unused84",
	4085: "readlink",
	4086: "uselib",
	4087: "swapon",
	4088: "reboot",
	4089: "readdir",
	4090: "mmap",
	4091: "munmap",
	4092: "truncate",
	4093: "ftruncate",
	4094: "fchmod",
	4095: "fchown",
	4096: "getpriority",
	4097: "setpriority",
	4098: "profil",
	4099: "statfs",
	4100: "fstatfs",
	4101: "ioperm",
	4102: "socketcall",
	4103: "syslog",
	4104: "setitimer",
	4105: "getitimer",
	4106: "stat",
	4107: "lstat",
	4108: "fstat",
	4109: "unused109",
	4110: "iopl",
	4111: "vhangup",
	4112: "idle",
	4113: "vm86",
	4114: "wait4",
	4115: "swapoff",
	4116: "sysinfo",
	4117: "ipc",
	4118: "fsync",
	4119: "sigreturn",
	4120: "clone",
	4121: "setdomainname",
	4122: "uname",
	4123: "modify_ldt",
	4124: "adjtimex",
	4125: "mprotect",
	4126: "sigprocmask",
	4127: "create_module",
	4128: "init_module",
	4129: "delete_module",
	4130: "get_kernel_syms",
	4131: "quotactl",
	4132: "getpgid",
	4133: "fchdir",
	4134: "bdflush",
	4135: "sysfs",
	4136: "personality",
	4137: "afs_syscall",
	4138: "setfsuid",
	4139: "setfsgid",
	4140: "_llseek",
	4141: "getdents",
	4142: "_newselect",
	4143: "flock",
	4144: "msync",
	4145: "readv",
	4146: "writev",
	4147: "cacheflush",
	4148: "cachectl",
	4149: "sysmips",
	4150: "unused150",
	4151: "getsid",
	4152: "fdatasync",
	4153: "_sysctl",
	4154: "mlock",
	4155: "munlock",
	4156: "mlockall",
	4157: "munlockall",
	4158: "sched_setparam",
	4159: "sched_getparam",
	4160: "sched_setscheduler",
	4161: "sched_getscheduler",
	4162: "sched_yield",
	4163: "sched_get_priority_max",
	4164: "sched_get_priority_min",
	4165: "sched_rr_get_interval",
	4166: "nanosleep",
	4167: "mremap",
	4168: "accept",
	4169: "bind",
	4170: "connect",
	4171: "getpeername",
	4172: "getsockname",
	4173: "getsockopt",
	4174: "listen",
	4175: "recv",
	4176: "recvfrom",
	4177: "recvmsg",
	4178: "send",
	4179: "sendmsg",
	4180: "sendto",
	4181: "setsockopt",
	4182: "shutdown",
	4183: "socket",
	4184: "socketpair",
	4185: "setresuid",
	4186: "getresuid",
	4187: "query_module",
	4188: "poll",
	4189: "nfsservctl",
	4190: "setresgid",
	4191: "getresgid",
	4192: "prctl",
	4193: "rt_sigreturn",
	4194: "rt_sigaction",
	4195: "rt_sigprocmask",
	4196: "rt_sigpending",
	4197: "rt_sigtimedwait",
	4198: "rt_sigqueueinfo",
	4199: "rt_sigsuspend",
	4200: "pread64",
	4201: "pwrite64",
	4202: "chown",
	4203: "getcwd",
	4204: "capget",
	4205: "capset",
	4206: "sigaltstack",
	4207: "sendfile",
	4208: "getpmsg",
	4209: "putpmsg",
	4210: "mmap2",
	4211: "truncate64",
	4212: "ftruncate64",
	4213: "stat64",
	4214: "lstat64",
	4215: "fstat64",
	4216: "pivot_root",
	4217: "mincore",
	4218: "madvise",
	4219: "getdents64",
	4220: "fcntl64",
	4221: "reserved221",
	4222: "gettid",
	4223: "readahead",
	4224: "setxattr",
	4225: "lsetxattr",
	4226: "fsetxattr",
	4227: "getxattr",
	4228: "lgetxattr",
	4229: "fgetxattr",
	4230: "listxattr",
	4231: "llistxattr",
	4232: "flistxattr",
	4233: "removexattr",
	4234: "lremovexattr",
	4235: "fremovexattr",
	4236: "tkill",
	4237: "sendfile64",
	4238: "futex",
	4239: "sched_setaffinity",
	4240: "sched_getaffinity",
	4241: "io_setup",
	4242: "io_destroy",
	4243: "io_getevents",
	4244: "io_submit",
	4245: "io_cancel",
	4246: "exit_group",
	4247: "lookup_dcookie",
	4248: "epoll_create",
	4249: "epoll_ctl",
	4250: "epoll_wait",
	4251: "remap_file_pages",
	4252: "set_tid_address",
	4253: "restart_syscall",
	4254: "fadvise64",
	4255: "statfs64",
	4256: "fstatfs64",
	4257: "timer_create",
	4258: "timer_settime",
	4259: "timer_gettime",
	4260: "timer_getoverrun",
	4261: "timer_delete",
	4262: "clock_settime",
	4263: "clock_gettime",
	4264: "clock_getres",
	4265: "clock_nanosleep",
	4266: "tgkill",
	4267: "utimes",
	4268: "mbind",
	4269: "get_mempolicy",
	4270: "set_mempolicy",
	4271: "mq_open",
	4272: "mq_unlink",
	4273: "mq_timedsend",
	4274: "mq_timedreceive",
	4275: "mq_notify",
	4276: "mq_getsetattr",
	4277: "vserver",
	4278: "waitid",
	4280: "add_key",
	4281: "request_key",
	4282: "keyctl",
	4283: "set_thread_area",
	4284: "inotify_init",
	4285: "inotify_add_watch",
	4286: "inotify_rm_watch",
	4287: "migrate_pages",
	4288: "openat",
	4289: "mkdirat",
	4290: "mknodat",
	4291: "fchownat",
	4292: "futimesat",
	4293: "fstatat64",
	4294: "unlinkat",
	4295: "renameat",
	4296: "linkat",
	4297: "symlinkat",
	4298: "readlinkat",
	4299: "fchmodat",
	4300: "faccessat",
	4301: "pselect6",
	4302: "ppoll",
	4303: "unshare",
	4304: "splice",
	4305: "sync_file_range",
	4306: "tee",
	4307: "vmsplice",
	4308: "move_pages",
	4309: "set_robust_list",
	4310: "get_robust_list",
	4311: "kexec_load",
	4312: "getcpu",
	4313: "epoll_pwait",
	4314: "ioprio_set",
	4315: "ioprio_get",
	4316: "utimensat",
	4317: "signalfd",
	4318: "timerfd",
	4319: "eventfd",
	4320: "fallocate",
	4321: "timerfd_create",
	4322: "timerfd_gettime",
	4323: "timerfd_settime",
	4324: "signalfd4",
	4325: "eventfd2",
	4326: "epoll_create1",
	4327: "dup3",
	4328: "pipe2",
	4329: "inotify_init1",
	4330: "preadv",
	4331: "pwritev",
	4332: "rt_tgsigqueueinfo",
	4333: "perf_event_open",
	4334: "accept4",
	4335: "recvmmsg",
	4336: "fanotify_init",
	4337: "fanotify_mark",
	4338: "prlimit64",
	4339: "name_to_handle_at",
	4340: "open_by_handle_at",
	4341: "clock_adjtime",
	4342: "syncfs",
	4343: "sendmmsg",
	4344: "setns",
	4345: "process_vm_readv",
	4346: "process_vm_writev",
	5000: "read",
	5001: "write",
	5002: "open",
	5003: "close",
	5004: "stat",
	5005: "fstat",
	5006: "lstat",
	5007: "poll",
	5008: "lseek",
	5009: "mmap",
	5010: "mprotect",
	5011: "munmap",
	5012: "brk",
	5013: "rt_sigaction",
	5014: "rt_sigprocmask",
	5015: "ioctl",
	5016: "pread64",
	5017: "pwrite64",
	5018: "readv",
	5019: "writev",
	5020: "access",
	5021: "pipe",
	5022: "_newselect",
	5023: "sched_yield",
	5024: "mremap",
	5025: "msync",
	5026: "mincore",
	5027: "madvise",
	5028: "shmget",
	5029: "shmat",
	5030: "shmctl",
	5031: "dup",
	5032: "dup2",
	5033: "pause",
	5034: "nanosleep",
	5035: "getitimer",
	5036: "setitimer",
	5037: "alarm",
	5038: "getpid",
	5039: "sendfile",
	5040: "socket",
	5041: "connect",
	5042: "accept",
	5043: "sendto",
	5044: "recvfrom",
	5045: "sendmsg",
	5046: "recvmsg",
	5047: "shutdown",
	5048: "bind",
	5049: "listen",
	5050: "getsockname",
	5051: "getpeername",
	5052: "socketpair",
	5053: "setsockopt",
	5054: "getsockopt",
	5055: "clone",
	5056: "fork",
	5057: "execve",
	5058: "exit",
	5059: "wait4",
	5060: "kill",
	5061: "uname",
	5062: "semget",
	5063: "semop",
	5064: "semctl",
	5065: "shmdt",
	5066: "msgget",
	5067: "msgsnd",
	5068: "msgrcv",
	5069: "msgctl",
	5070: "fcntl",
	5071: "flock",
	5072: "fsync",
	5073: "fdatasync",
	5074: "truncate",
	5075: "ftruncate",
	5076: "getdents",
	5077: "getcwd",
	5078: "chdir",
	5079: "fchdir",
	5080: "rename",
	5081: "mkdir",
	5082: "rmdir",
	5083: "creat",
	5084: "link",
	5085: "unlink",
	5086: "symlink",
	5087: "readlink",
	5088: "chmod",
	5089: "fchmod",
	5090: "chown",
	5091: "fchown",
	5092: "lchown",
	5093: "umask",
	5094: "gettimeofday",
	5095: "getrlimit",
	5096: "getrusage",
	5097: "sysinfo",
	5098: "times",
	5099: "ptrace",
	5100: "getuid",
	5101: "syslog",
	5102: "getgid",
	5103: "setuid",
	5104: "setgid",
	5105: "geteuid",
	5106: "getegid",
	5107: "setpgid",
	5108: "getppid",
	5109: "getpgrp",
	5110: "setsid",
	5111: "setreuid",
	5112: "setregid",
	5113: "getgroups",
	5114: "setgroups",
	5115: "setresuid",
	5116: "getresuid",
	5117: "setresgid",
	5118: "getresgid",
	5119: "getpgid",
	5120: "setfsuid",
	5121: "setfsgid",
	5122: "getsid",
	5123: "capget",
	5124: "capset",
	5125: "rt_sigpending",
	5126: "rt_sigtimedwait",
	5127: "rt_sigqueueinfo",
	5128: "rt_sigsuspend",
	5129: "sigaltstack",
	5130: "utime",
	5131: "mknod",
	5132: "personality",
	5133: "ustat",
	5134: "statfs",
	5135: "fstatfs",
	5136: "sysfs",
	5137: "getpriority",
	5138: "setpriority",
	5139: "sched_setparam",
	5140: "sched_getparam",
	5141: "sched_setscheduler",
	5142: "sched_getscheduler",
	5143: "sched_get_priority_max",
	5144: "sched_get_priority_min",
	5145: "sched_rr_get_interval",
	5146: "mlock",
	5147: "munlock",
	5148: "mlockall",
	5149: "munlockall",
	5150: "vhangup",
	5151: "pivot_root",
	5152: "_sysctl",
	5153: "prctl",
	5154: "adjtimex",
	5155: "setrlimit",
	5156: "chroot",
	5157: "sync",
	5158: "acct",
	5159: "settimeofday",
	5160: "mount",
	5161: "umount2",
	5162: "swapon",
	5163: "swapoff",
	5164: "reboot",
	5165: "sethostname",
	5166: "setdomainname",
	5167: "create_module",
	5168: "init_module",
	5169: "delete_module",
	5170: "get_kernel_syms",
	5171: "query_module",
	5172: "quotactl",
	5173: "nfsservctl",
	5174: "getpmsg",
	5175: "putpmsg",
	5176: "afs_syscall",
	5177: "reserved177",
	5178: "gettid",
	5179: "readahead",
	5180: "setxattr",
	5181: "lsetxattr",
	5182: "fsetxattr",
	5183: "getxattr",
	5184: "lgetxattr",
	5185: "fgetxattr",
	5186: "listxattr",
	5187: "llistxattr",
	5188: "flistxattr",
	5189: "removexattr",
	5190: "lremovexattr",
	5191: "fremovexattr",
	5192: "tkill",
	5193: "reserved193",
	5194: "futex",
	5195: "sched_setaffinity",
	5196: "sched_getaffinity",
	5197: "cacheflush",
	5198: "cachectl",
	5199: "sysmips",
	5200: "io_setup",
	5201: "io_destroy",
	5202: "io_getevents",
	5203: "io_submit",
	5204: "io_cancel",
	5205: "exit_group",
	5206: "lookup_dcookie",
	5207: "epoll_create",
	5208: "epoll_ctl",
	5209: "epoll_wait",
	5210: "remap_file_pages",
	5211: "rt_sigreturn",
	5212: "set_tid_address",
	5213: "restart_syscall",
	5214: "semtimedop",
	5215: "fadvise64",
	5216: "timer_create",
	5217: "timer_settime",
	5218: "timer_gettime",
	5219: "timer_getoverrun",
	5220: "timer_delete",
	5221: "clock_settime",
	5222: "clock_gettime",
	5223: "clock_getres",
	5224: "clock_nanosleep",
	5225: "tgkill",
	5226: "utimes",
	5227: "mbind",
	5228: "get_mempolicy",
	5229: "set_mempolicy",
	5230: "mq_open",
	5231: "mq_unlink",
	5232: "mq_timedsend",
	5233: "mq_timedreceive",
	5234: "mq_notify",
	5235: "mq_getsetattr",
	5236: "vserver",
	5237: "waitid",
	5239: "add_key",
	5240: "request_key",
	5241: "keyctl",
	5242: "set_thread_area",
	5243: "inotify_init",
	5244: "inotify_add_watch",
	5245: "inotify_rm_watch",
	5246: "migrate_pages",
	5247: "openat",
	5248: "mkdirat",
	5249: "mknodat",
	5250: "fchownat",
	5251: "futimesat",
	5252: "newfstatat",
	5253: "unlinkat",
	5254: "renameat",
	5255: "linkat",
	5256: "symlinkat",
	5257: "readlinkat",
	5258: "fchmodat",
	5259: "faccessat",
	5260: "pselect6",
	5261: "ppoll",
	5262: "unshare",
	5263: "splice",
	5264: "sync_file_range",
	5265: "tee",
	5266: "vmsplice",
	5267: "move_pages",
	5268: "set_robust_list",
	5269: "get_robust_list",
	5270: "kexec_load",
	5271: "getcpu",
	5272: "epoll_pwait",
	5273: "ioprio_set",
	5274: "ioprio_get",
	5275: "utimensat",
	5276: "signalfd",
	5277: "timerfd",
	5278: "eventfd",
	5279: "fallocate",
	5280: "timerfd_create",
	5281: "timerfd_gettime",
	5282: "timerfd_settime",
	5283: "signalfd4",
	5284: "eventfd2",
	5285: "epoll_create1",
	5286: "dup3",
	5287: "pipe2",
	5288: "inotify_init1",
	5289: "preadv",
	5290: "pwritev",
	5291: "rt_tgsigqueueinfo",
	5292: "perf_event_open",
	5293: "accept4",
	5294: "recvmmsg",
	5295: "fanotify_init",
	5296: "fanotify_mark",
	5297: "prlimit64",
	5298: "name_to_handle_at",
	5299: "open_by_handle_at",
	5300: "clock_adjtime",
	5301: "syncfs",
	5302: "sendmmsg",
	5303: "setns",
	5304: "process_vm_readv",
	5305: "process_vm_writev",
	6000: "read",
	6001: "write",
	6002: "open",
	6003: "close",
	6004: "stat",
	6005: "fstat",
	6006: "lstat",
	6007: "poll",
	6008: "lseek",
	6009: "mmap",
	6010: "mprotect",
	6011: "munmap",
	6012: "brk",
	6013: "rt_sigaction",
	6014: "rt_sigprocmask",
	6015: "ioctl",
	6016: "pread64",
	6017: "pwrite64",
	6018: "readv",
	6019: "writev",
	6020: "access",
	6021: "pipe",
	6022: "_newselect",
	6023: "sched_yield",
	6024: "mremap",
	6025: "msync",
	6026: "mincore",
	6027: "madvise",
	6028: "shmget",
	6029: "shmat",
	6030: "shmctl",
	6031: "dup",
	6032: "dup2",
	6033: "pause",
	6034: "nanosleep",
	6035: "getitimer",
	6036: "setitimer",
	6037: "alarm",
	6038: "getpid",
	6039: "sendfile",
	6040: "socket",
	6041: "connect",
	6042: "accept",
	6043: "sendto",
	6044: "recvfrom",
	6045: "sendmsg",
	6046: "recvmsg",
	6047: "shutdown",
	6048: "bind",
	6049: "listen",
	6050: "getsockname",
	6051: "getpeername",
	6052: "socketpair",
	6053: "setsockopt",
	6054: "getsockopt",
	6055: "clone",
	6056: "fork",
	6057: "execve",
	6058: "exit",
	6059: "wait4",
	6060: "kill",
	6061: "uname",
	6062: "semget",
	6063: "semop",
	6064: "semctl",
	6065: "shmdt",
	6066: "msgget",
	6067: "msgsnd",
	6068: "msgrcv",
	6069: "msgctl",
	6070: "fcntl",
	6071: "flock",
	6072: "fsync",
	6073: "fdatasync",
	6074: "truncate",
	6075: "ftruncate",
	6076: "getdents",
	6077: "getcwd",
	6078: "chdir",
	6079: "fchdir",
	6080: "rename",
	6081: "mkdir",
	6082: "rmdir",
	6083: "creat",
	6084: "link",
	6085: "unlink",
	6086: "symlink",
	6087: "readlink",
	6088: "chmod",
	6089: "fchmod",
	6090: "chown",
	6091: "fchown",
	6092: "lchown",
	6093: "umask",
	6094: "gettimeofday",
	6095: "getrlimit",
	6096: "getrusage",
	6097: "sysinfo",
	6098: "times",
	6099: "ptrace",
	6100: "getuid",
	6101: "syslog",
	6102: "getgid",
	6103: "setuid",
	6104: "setgid",
	6105: "geteuid",
	6106: "getegid",
	6107: "setpgid",
	6108: "getppid",
	6109: "getpgrp",
	6110: "setsid",
	6111: "setreuid",
	6112: "setregid",
	6113: "getgroups",
	6114: "setgroups",
	6115: "setresuid",
	6116: "getresuid",
	6117: "setresgid",
	6118: "getresgid",
	6119: "getpgid",
	6120: "setfsuid",
	6121: "setfsgid",
	6122: "getsid",
	6123: "capget",
	6124: "capset",
	6125: "rt_sigpending",
	6126: "rt_sigtimedwait",
	6127: "rt_sigqueueinfo",
	6128: "rt_sigsuspend",
	6129: "sigaltstack",
	6130: "utime",
	6131: "mknod",
	6132: "personality",
	6133: "ustat",
	6134: "statfs",
	6135: "fstatfs",
	6136: "sysfs",
	6137: "getpriority",
	6138: "setpriority",
	6139: "sched_setparam",
	6140: "sched_getparam",
	6141: "sched_setscheduler",
	6142: "sched_getscheduler",
	6143: "sched_get_priority_max",
	6144: "sched_get_priority_min",
	6145: "sched_rr_get_interval",
	6146: "mlock",
	6147: "munlock",
	6148: "mlockall",
	6149: "munlockall",
	6150: "vhangup",
	6151: "pivot_root",
	6152: "_sysctl",
	6153: "prctl",
	6154: "adjtimex",
	6155: "setrlimit",
	6156: "chroot",
	6157: "sync",
	6158: "acct",
	6159: "settimeofday",
	6160: "mount",
	6161: "umount2",
	6162: "swapon",
	6163: "swapoff",
	6164: "reboot",
	6165: "sethostname",
	6166: "setdomainname",
	6167: "create_module",
	6168: "init_module",
	6169: "delete_module",
	6170: "get_kernel_syms",
	6171: "query_module",
	6172: "quotactl",
	6173: "nfsservctl",
	6174: "getpmsg",
	6175: "putpmsg",
	6176: "afs_syscall",
	6177: "reserved177",
	6178: "gettid",
	6179: "readahead",
	6180: "setxattr",
	6181: "lsetxattr",
	6182: "fsetxattr",
	6183: "getxattr",
	6184: "lgetxattr",
	6185: "fgetxattr",
	6186: "listxattr",
	6187: "llistxattr",
	6188: "flistxattr",
	6189: "removexattr",
	6190: "lremovexattr",
	6191: "fremovexattr",
	6192: "tkill",
	6193: "reserved193",
	6194: "futex",
	6195: "sched_setaffinity",
	6196: "sched_getaffinity",
	6197: "cacheflush",
	6198: "cachectl",
	6199: "sysmips",
	6200: "io_setup",
	6201: "io_destroy",
	6202: "io_getevents",
	6203: "io_submit",
	6204: "io_cancel",
	6205: "exit_group",
	6206: "lookup_dcookie",
	6207: "epoll_create",
	6208: "epoll_ctl",
	6209: "epoll_wait",
	6210: "remap_file_pages",
	6211: "rt_sigreturn",
	6212: "fcntl64",
	6213: "set_tid_address",
	6214: "restart_syscall",
	6215: "semtimedop",
	6216: "fadvise64",
	6217: "statfs64",
	6218: "fstatfs64",
	6219: "sendfile64",
	6220: "timer_create",
	6221: "timer_settime",
	6222: "timer_gettime",
	6223: "timer_getoverrun",
	6224: "timer_delete",
	6225: "clock_settime",
	6226: "clock_gettime",
	6227: "clock_getres",
	6228: "clock_nanosleep",
	6229: "tgkill",
	6230: "utimes",
	6231: "mbind",
	6232: "get_mempolicy",
	6233: "set_mempolicy",
	6234: "mq_open",
	6235: "mq_unlink",
	6236: "mq_timedsend",
	6237: "mq_timedreceive",
	6238: "mq_notify",
	6239: "mq_getsetattr",
	6240: "vserver",
	6241: "waitid",
	6243: "add_key",
	6244: "request_key",
	6245: "keyctl",
	6246: "set_thread_area",
	6247: "inotify_init",
	6248: "inotify_add_watch",
	6249: "inotify_rm_watch",
	6250: "migrate_pages",
	6251: "openat",
	6252: "mkdirat",
	6253: "mknodat",
	6254: "fchownat",
	6255: "futimesat",
	6256: "newfstatat",
	6257: "unlinkat",
	6258: "renameat",
	6259: "linkat",
	6260: "symlinkat",
	6261: "readlinkat",
	6262: "fchmodat",
	6263: "faccessat",
	6264: "pselect6",
	6265: "ppoll",
	6266: "unshare",
	6267: "splice",
	6268: "sync_file_range",
	6269: "tee",
	6270: "vmsplice",
	6271: "move_pages",
	6272: "set_robust_list",
	6273: "get_robust_list",
	6274: "kexec_load",
	6275: "getcpu",
	6276: "epoll_pwait",
	6277: "ioprio_set",
	6278: "ioprio_get",
	6279: "utimensat",
	6280: "signalfd",
	6281: "timerfd",
	6282: "eventfd",
	6283: "fallocate",
	6284: "timerfd_create",
	6285: "timerfd_gettime",
	6286: "timerfd_settime",
	6287: "signalfd4",
	6288: "eventfd2",
	6289: "epoll_create1",
	6290: "dup3",
	6291: "pipe2",
	6292: "inotify_init1",
	6293: "preadv",
	6294: "pwritev",
	6295: "rt_tgsigqueueinfo",
	6296: "perf_event_open",
	6297: "accept4",
	6298: "recvmmsg",
	6299: "getdents64",
	6300: "fanotify_init",
	6301: "fanotify_mark",
	6302: "prlimit64",
	6303: "name_to_handle_at",
	6304: "open_by_handle_at",
	6305: "clock_adjtime",
	6306: "syncfs",
	6307: "sendmmsg",
	6308: "setns",
	6309: "process_vm_readv",
	6310: "process_vm_writev",
}
