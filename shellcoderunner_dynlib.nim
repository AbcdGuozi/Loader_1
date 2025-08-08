import dynlib

type
  LPVOID = pointer
  SIZE_T = uint64
  DWORD = uint32
  HANDLE = pointer
  LPCSTR = cstring
  LPTHREAD_START_ROUTINE = proc(lpParameter: pointer): int32 {.stdcall.}

# 加载库和声明
let k32 = loadLib("kernel32.dll")
assert k32 != nil, "loadLib kernel32.dll failed"

proc GetProcAddress(hModule: pointer, procName: cstring): pointer #这个只能静态绑定，nim2.*把getProcAddr删除了
  {.stdcall, importc: "GetProcAddress", dynlib: "kernel32.dll".}  #static load only, nim2.* removed the getProcAddr()funciton

let virtualAlloc = cast[proc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD): LPVOID {.stdcall.}](GetProcAddress(k32, "VirtualAlloc"))
let createThread = cast[proc(lpThreadAttributes: LPVOID, dwStackSize: SIZE_T,
                             lpStartAddress: LPTHREAD_START_ROUTINE,
                             lpParameter: LPVOID, dwCreationFlags: DWORD,
                             lpThreadId: ptr DWORD): HANDLE {.stdcall.}](GetProcAddress(k32, "CreateThread"))
let waitForSingleObject = cast[proc(hHandle: HANDLE, dwMilliseconds: DWORD): DWORD {.stdcall.}](GetProcAddress(k32, "WaitForSingleObject"))

let ntdll = loadLib("ntdll.dll")
assert ntdll != nil, "loadLib ntdll.dll failed"
let rtlMoveMemory = cast[proc(dest, src: pointer, size: SIZE_T) {.stdcall.}](GetProcAddress(ntdll, "RtlMoveMemory"))

let user32 = loadLib("user32.dll")
assert user32 != nil, "loadLib user32.dll failed"

var shellcode: seq[byte] = @[
  0x90,0x90,0xC3                       # NOP NOP RET
]

let adr = virtualAlloc(nil, SIZE_T(shellcode.len), 0x3000, 0x40)
assert adr != nil, "virtualAlloc failed"

rtlMoveMemory(adr, unsafeAddr shellcode[0], SIZE_T(shellcode.len))

let hThread = createThread(nil, 0, cast[LPTHREAD_START_ROUTINE](adr), nil, 0, nil)
assert hThread != nil, "createThread failed"

discard waitForSingleObject(hThread, 0xFFFFFFFF'u32)
