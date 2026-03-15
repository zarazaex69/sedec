package abi

import "github.com/zarazaex69/sedec/pkg/ir"

// linuxAMD64SyscallTable maps syscall numbers to signatures for Linux x86_64.
// source: linux kernel arch/x86/entry/syscalls/syscall_64.tbl (v6.x)
// parameter registers follow the Linux syscall ABI:
//
//	rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
//
// return value is in rax (negative errno on error).
//
//nolint:gochecknoglobals // read-only lookup table, never mutated
var linuxAMD64SyscallTable = map[uint64]SyscallSignature{
	0: {
		Name: "read", Number: 0, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "count", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdx"},
		},
	},
	1: {
		Name: "write", Number: 1, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "count", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdx"},
		},
	},
	2: {
		Name: "open", Number: 2, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
			{Name: "mode", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
	3: {
		Name: "close", Number: 3, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
		},
	},
	4: {
		Name: "stat", Number: 4, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "statbuf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
		},
	},
	5: {
		Name: "fstat", Number: 5, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "statbuf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
		},
	},
	6: {
		Name: "lstat", Number: 6, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "statbuf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
		},
	},
	7: {
		Name: "poll", Number: 7, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fds", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
			{Name: "nfds", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rsi"},
			{Name: "timeout", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	8: {
		Name: "lseek", Number: 8, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "offset", Type: ir.IntType{Width: ir.Size8, Signed: true}, Register: "rsi"},
			{Name: "whence", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	9: {
		Name: "mmap", Number: 9, OS: OSLinuxAMD64,
		ReturnType: ir.PointerType{Pointee: ir.VoidType{}},
		Params: []SyscallParam{
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
			{Name: "length", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
			{Name: "prot", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r10"},
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r8"},
			{Name: "offset", Type: ir.IntType{Width: ir.Size8, Signed: true}, Register: "r9"},
		},
	},
	10: {
		Name: "mprotect", Number: 10, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
			{Name: "len", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
			{Name: "prot", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	11: {
		Name: "munmap", Number: 11, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
			{Name: "length", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
		},
	},
	12: {
		Name: "brk", Number: 12, OS: OSLinuxAMD64,
		ReturnType: ir.PointerType{Pointee: ir.VoidType{}},
		Params: []SyscallParam{
			{Name: "brk", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
		},
	},
	13: {
		Name: "rt_sigaction", Number: 13, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "signum", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "act", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "oldact", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "sigsetsize", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "r10"},
		},
	},
	14: {
		Name: "rt_sigprocmask", Number: 14, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "how", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "set", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "oldset", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "sigsetsize", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "r10"},
		},
	},
	22: {
		Name: "pipe", Number: 22, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pipefd", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdi"},
		},
	},
	32: {
		Name: "dup", Number: 32, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "oldfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
		},
	},
	33: {
		Name: "dup2", Number: 33, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "oldfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "newfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
		},
	},
	39: {
		Name: "getpid", Number: 39, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params:     []SyscallParam{},
	},
	41: {
		Name: "socket", Number: 41, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "domain", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "type", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
			{Name: "protocol", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	42: {
		Name: "connect", Number: 42, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "addrlen", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
	43: {
		Name: "accept", Number: 43, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "addrlen", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: false}}, Register: "rdx"},
		},
	},
	44: {
		Name: "sendto", Number: 44, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "len", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdx"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r10"},
			{Name: "dest_addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "addrlen", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	45: {
		Name: "recvfrom", Number: 45, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "len", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdx"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r10"},
			{Name: "src_addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "addrlen", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: false}}, Register: "r9"},
		},
	},
	49: {
		Name: "bind", Number: 49, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "addr", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "addrlen", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
	50: {
		Name: "listen", Number: 50, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "sockfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "backlog", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
		},
	},
	56: {
		Name: "clone", Number: 56, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "flags", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdi"},
			{Name: "stack", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "parent_tid", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdx"},
			{Name: "child_tid", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "r10"},
			{Name: "tls", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "r8"},
		},
	},
	57: {
		Name: "fork", Number: 57, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params:     []SyscallParam{},
	},
	59: {
		Name: "execve", Number: 59, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "argv", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}}, Register: "rsi"},
			{Name: "envp", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}}, Register: "rdx"},
		},
	},
	60: {
		Name: "exit", Number: 60, OS: OSLinuxAMD64,
		ReturnType: ir.VoidType{},
		Params: []SyscallParam{
			{Name: "error_code", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
		},
	},
	61: {
		Name: "wait4", Number: 61, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pid", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "wstatus", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rsi"},
			{Name: "options", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
			{Name: "rusage", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r10"},
		},
	},
	62: {
		Name: "kill", Number: 62, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pid", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "sig", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
		},
	},
	63: {
		Name: "uname", Number: 63, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
		},
	},
	72: {
		Name: "fcntl", Number: 72, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "cmd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
			{Name: "arg", Type: ir.IntType{Width: ir.Size8, Signed: true}, Register: "rdx"},
		},
	},
	78: {
		Name: "getdents", Number: 78, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdi"},
			{Name: "dirp", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "count", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
	79: {
		Name: "getcwd", Number: 79, OS: OSLinuxAMD64,
		ReturnType: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}},
		Params: []SyscallParam{
			{Name: "buf", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "size", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
		},
	},
	87: {
		Name: "unlink", Number: 87, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
		},
	},
	89: {
		Name: "readlink", Number: 89, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rdi"},
			{Name: "buf", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rsi"},
			{Name: "bufsiz", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rdx"},
		},
	},
	102: {
		Name: "getuid", Number: 102, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: false},
		Params:     []SyscallParam{},
	},
	104: {
		Name: "getgid", Number: 104, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: false},
		Params:     []SyscallParam{},
	},
	105: {
		Name: "setuid", Number: 105, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "uid", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdi"},
		},
	},
	106: {
		Name: "setgid", Number: 106, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "gid", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdi"},
		},
	},
	110: {
		Name: "getppid", Number: 110, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params:     []SyscallParam{},
	},
	158: {
		Name: "arch_prctl", Number: 158, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "code", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "addr", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
		},
	},
	186: {
		Name: "gettid", Number: 186, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params:     []SyscallParam{},
	},
	202: {
		Name: "futex", Number: 202, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "uaddr", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdi"},
			{Name: "futex_op", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
			{Name: "val", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "timeout", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r10"},
			{Name: "uaddr2", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "r8"},
			{Name: "val3", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	217: {
		Name: "getdents64", Number: 217, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "fd", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdi"},
			{Name: "dirp", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
			{Name: "count", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
	228: {
		Name: "clock_gettime", Number: 228, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "clockid", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "tp", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rsi"},
		},
	},
	231: {
		Name: "exit_group", Number: 231, OS: OSLinuxAMD64,
		ReturnType: ir.VoidType{},
		Params: []SyscallParam{
			{Name: "error_code", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
		},
	},
	257: {
		Name: "openat", Number: 257, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "dirfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rsi"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
			{Name: "mode", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r10"},
		},
	},
	262: {
		Name: "fstatat", Number: 262, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "dirfd", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdi"},
			{Name: "pathname", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size1, Signed: true}}, Register: "rsi"},
			{Name: "statbuf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r10"},
		},
	},
	293: {
		Name: "pipe2", Number: 293, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "pipefd", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdi"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rsi"},
		},
	},
	318: {
		Name: "getrandom", Number: 318, OS: OSLinuxAMD64,
		ReturnType: ir.IntType{Width: ir.Size8, Signed: true},
		Params: []SyscallParam{
			{Name: "buf", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdi"},
			{Name: "buflen", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "rsi"},
			{Name: "flags", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
		},
	},
}
