package abi

import "github.com/zarazaex69/sedec/pkg/ir"

// windowsNTSyscallTable maps Windows NT Native API syscall numbers to signatures.
// source: ntdll.dll syscall stubs (Windows 10 21H2 / Windows 11 22H2).
// syscall numbers are NOT stable across Windows versions — these reflect a common
// modern baseline. the table covers the most frequently encountered Nt* functions.
//
// Windows NT syscall ABI (x64):
//
//	rcx=arg1, rdx=arg2, r8=arg3, r9=arg4, stack=arg5+
//	return value: NTSTATUS in rax (0 = STATUS_SUCCESS, negative = error)
//
//nolint:gochecknoglobals // read-only lookup table, never mutated
var windowsNTSyscallTable = map[uint64]SyscallSignature{
	0x00: {
		Name: "NtReadFile", Number: 0x00, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "Event", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "ApcRoutine", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ApcContext", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x01: {
		Name: "NtWriteFile", Number: 0x01, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "Event", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "ApcRoutine", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ApcContext", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x02: {
		Name: "NtCreateFile", Number: 0x02, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "IoStatusBlock", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x03: {
		Name: "NtOpenFile", Number: 0x03, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "IoStatusBlock", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x04: {
		Name: "NtClose", Number: 0x04, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "Handle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
		},
	},
	0x05: {
		Name: "NtQueryInformationFile", Number: 0x05, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "IoStatusBlock", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "FileInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "Length", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x06: {
		Name: "NtSetInformationFile", Number: 0x06, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "IoStatusBlock", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "FileInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "Length", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x12: {
		Name: "NtAllocateVirtualMemory", Number: 0x12, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rdx"},
			{Name: "ZeroBits", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "r8"},
			{Name: "RegionSize", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}, Register: "r9"},
		},
	},
	0x1e: {
		Name: "NtFreeVirtualMemory", Number: 0x1e, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rdx"},
			{Name: "RegionSize", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}, Register: "r8"},
			{Name: "FreeType", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x23: {
		Name: "NtProtectVirtualMemory", Number: 0x23, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rdx"},
			{Name: "RegionSize", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: false}}, Register: "r8"},
			{Name: "NewProtect", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x25: {
		Name: "NtQueryVirtualMemory", Number: 0x25, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "MemoryInformationClass", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r8"},
			{Name: "MemoryInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x26: {
		Name: "NtOpenProcess", Number: 0x26, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ClientId", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x2c: {
		Name: "NtTerminateProcess", Number: 0x2c, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ExitStatus", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	0x36: {
		Name: "NtCreateThread", Number: 0x36, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ThreadHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x52: {
		Name: "NtOpenThread", Number: 0x52, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ThreadHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ClientId", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x55: {
		Name: "NtTerminateThread", Number: 0x55, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ThreadHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ExitStatus", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
		},
	},
	0x3a: {
		Name: "NtCreateKey", Number: 0x3a, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "KeyHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "TitleIndex", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x3f: {
		Name: "NtOpenKey", Number: 0x3f, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "KeyHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
		},
	},
	0x5a: {
		Name: "NtQueryValueKey", Number: 0x5a, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "KeyHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ValueName", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "KeyValueInformationClass", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r8"},
			{Name: "KeyValueInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x7a: {
		Name: "NtSetValueKey", Number: 0x7a, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "KeyHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ValueName", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "TitleIndex", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r8"},
			{Name: "Type", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x0f: {
		Name: "NtQuerySystemInformation", Number: 0x0f, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "SystemInformationClass", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rcx"},
			{Name: "SystemInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "SystemInformationLength", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r8"},
			{Name: "ReturnLength", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: false}}, Register: "r9"},
		},
	},
	0x19: {
		Name: "NtQueryInformationProcess", Number: 0x19, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ProcessInformationClass", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "rdx"},
			{Name: "ProcessInformation", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ProcessInformationLength", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "r9"},
		},
	},
	0x48: {
		Name: "NtCreateSection", Number: 0x48, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "SectionHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "MaximumSize", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}, Register: "r9"},
		},
	},
	0x28: {
		Name: "NtMapViewOfSection", Number: 0x28, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "SectionHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "r8"},
			{Name: "ZeroBits", Type: ir.IntType{Width: ir.Size8, Signed: false}, Register: "r9"},
		},
	},
	0x40: {
		Name: "NtUnmapViewOfSection", Number: 0x40, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "ProcessHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "BaseAddress", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
		},
	},
	0x0e: {
		Name: "NtWaitForSingleObject", Number: 0x0e, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "Handle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "Alertable", Type: ir.BoolType{}, Register: "rdx"},
			{Name: "Timeout", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size8, Signed: true}}, Register: "r8"},
		},
	},
	0x98: {
		Name: "NtWaitForMultipleObjects", Number: 0x98, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "Count", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rcx"},
			{Name: "Handles", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rdx"},
			{Name: "WaitType", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r8"},
			{Name: "Alertable", Type: ir.BoolType{}, Register: "r9"},
		},
	},
	0x18: {
		Name: "NtCreateEvent", Number: 0x18, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "EventHandle", Type: ir.PointerType{Pointee: ir.PointerType{Pointee: ir.VoidType{}}}, Register: "rcx"},
			{Name: "DesiredAccess", Type: ir.IntType{Width: ir.Size4, Signed: false}, Register: "rdx"},
			{Name: "ObjectAttributes", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "EventType", Type: ir.IntType{Width: ir.Size4, Signed: true}, Register: "r9"},
		},
	},
	0x22: {
		Name: "NtSetEvent", Number: 0x22, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "EventHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "PreviousState", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdx"},
		},
	},
	0x14: {
		Name: "NtResetEvent", Number: 0x14, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "EventHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "PreviousState", Type: ir.PointerType{Pointee: ir.IntType{Width: ir.Size4, Signed: true}}, Register: "rdx"},
		},
	},
	0x08: {
		Name: "NtDeviceIoControlFile", Number: 0x08, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "Event", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "ApcRoutine", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ApcContext", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
	0x0d: {
		Name: "NtFsControlFile", Number: 0x0d, OS: OSWindowsNT,
		ReturnType: ir.IntType{Width: ir.Size4, Signed: true},
		Params: []SyscallParam{
			{Name: "FileHandle", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rcx"},
			{Name: "Event", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "rdx"},
			{Name: "ApcRoutine", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r8"},
			{Name: "ApcContext", Type: ir.PointerType{Pointee: ir.VoidType{}}, Register: "r9"},
		},
	},
}
