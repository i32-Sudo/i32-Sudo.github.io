---
layout: post
title:  "ThreadContext [EntryPoint] Register Spoofing (EIP/RIP) for x64 and x86 Intel/AMD"
---

In every thread has the **Entry-Point** Identifier usually stored in the register `EIP(x86)` or `RIP(x64)` Depending on if you are on x86 Systems or x64 Systems Usually defined by a 5-Byte `DWORD` Hex Address.

When a module like say **NTDLL** or **KERNEL32** Need to get the **Entry-Point** of a Thread or Program they will usually call to the **EIP/RIP** Registers in Memory for the Address and Scan the Memory From there...

![enter image description here](https://lh3.googleusercontent.com/pw/AP1GczN-L_t-Mq_I1f5puYkEIgfmxy_-QIDaNgvE0YXqc_Lw1Uo4-LyPvGL2qD-EsAd9o5BlCZnsYQ6ZtcXGr0I3DhZZ5r_VrrIkdPvNi3uVW3mhwFEcvBSJy6kof3S7bpexmqD18YYCRRKaG78O-DcMvsZMrOVHM4YDEwAPxIEVH0EszIaTYMR6JcRmGgbSmNDFSs7gMAbHQdKZ61cAYExVXKMyJ4OWqWpTuwWYwZzYS8mbgB6R0yyN9KjVtVWmW5PAHwa03umiLv8QwU5K7HPFiRrtZbQKOTd2721YeoqAqxzGFKWShI8XB-pjL6-AGPbI0_kf7G3lP4lAfRp-DGnqEkW2KUsv4ZuPSz8yQb4ugC-Jo3fhp7_XzWwt7AzaWCAAwZHGAh0C_9VysqIhdPO7rxjuaZ0qkaXmPfHVJJqmg3AYUsB500fW2R2_3ICwILSsqxcIepALo5RRGH7p3_MZwesVHe5tqcmq2NwhRzkA_nFkKLAxbI5a4xDWdLmTTD-auB_ovsleuh1GHuDI5iHUSxfXgDWV6WHbAbLiX01ipNd32xV-hEciu1qAE80vVEjUB3Byhs3JW8By64fk0fuOkidmE-5BHLFzqUVp3H3PjRtRXlgEK9-NxM8cEU5gaDNdTBk44gZ_6YxkPxI45PK_4mazFYnEvC8OlOHEKXGBY8WkzKtxig9wYM0Boh5OsDg8walMkmeJDdzD_NPmc4wpH6XfjcTB9NDQaH25hg-xiVqysCT6pkwiIsVI0240c5Tbi_E8Tn16KSlaYsiLUQ3HzJRAJ09SmygYRyfedYYU4bia21aEV21IhypuB2UuiNwrW2AvBjWPMZt1WSTerSaN_nYxEkT0KbHQJFgZcP95bHAprbiUjL0wOU8WN46EzbGVZCHlnWOoEp3L2q4Ryma2DU0N7l01HZy63wN-SII0oQLoPzNCv-iEcsb1Njf5OjiHMCj-9xtDKmby70Zy-Pw2cY-ys7BHAgqGiqQF4fgg5TG_sQ2TdW-8tiViCGmqPT2d-bjZpnyS0v2rKcCPycrvhkEB_R15W1AyWVF1F46DyYm5UmparEWCMbhRYPD5xMVTy4AQSiPm=w389-h324-s-no-gm?authuser=1)

We will be exploiting **Thread-Context** inside of C++ to change this Register to another Memory Address so that when **NTDLL** or **KERNEL32** Have to call this Register to get the Entry-Point it is returned another address, Also referred to as `Return Address Spoofing`.. It's a simple exploit inside of programs and can be used to hide and cloak threads behind another Entry-Point/Address...

Lets continue then...

# Exploitation
So how this will work is when you inject a **DLL** into a program it automatically creats a new thread to run our **DLL** Code, Of course it has to do so to run our code.. What we will do is create our own Function that will use `_RtlCreateUserThread` to Create a new thread with a Swapped/Spoofed `EIP/RIP` - `EntryPoint` and then kill the original thread created by the injector when it maps our **DLL**, This is useful because when the new thread is created to run our code its completely detached from our original EntryPoint / `DllMain` and along with that has a new fake `EntryPoint` that is just a random piece of Memory in our Program either generated with an Algorithm, stolen using another Thread's EntryPoint or just a manually set piece of memory...

We will begin exploiting this memory register to give it a fake address..
```cpp
/* Our function all this code will be in will take a void* to the thread we will make in our DLL */
/* And the HMODULE hModule of the Main Process */

void hyde::ThreadLocation(void* thread, HMODULE& hModule) {
	HMODULE hNtdll = LoadLibraryA("ntdll");
}
```

```cpp
auto newaddr = 00007FFF8797D540 /* Random Address in the Program */

/* We will use VirtualProtect to Allocate space for our "newaddr" */
/* The size of this thread will be an integer of 1000 however this can be changed... */
VirtualProtect((void*)newaddr, 1000, PAGE_EXECUTE_READWRITE, NULL);
```
Now that we have allocated a space for our "FakeRegion" Where the address will be returned.. Forr newaddr you could totally use a random address in Memory selected manually, Or use a function to get the `EIP` of Another thread in memory or you could use an algorithm to get a random address in memory, However all your threads HAVE to be above `7FFFFFFF...` in Memory, If not they will be flagged as a suspicious thread...

Next we will get the context and also suspend the thread at the same time (ON THE CPU REGISTER)
```cpp
CONTEXT cpuContext;
HANDLE cpuHandle = nullptr;
```
We will create these 2 Variables which will be filled with another call to **NTDLL**
```cpp
using _RtlCreateUserThread = NTSTATUS(NTAPI*)(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	PULONG StackReserved,
	PULONG StackCommit,
	void* StartAddress,
	void* StartParameter,
	PHANDLE ThreadHandle,
	void* ClientID
);
	
	_RtlCreateUserThread NtThread = (_RtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	NtThread(GetCurrentProcess(), nullptr, TRUE, NULL, NULL, NULL, (PTHREAD_START_ROUTINE)newaddr, hModule, &cpuHandle, NULL);
```
We will be using `_RtlCreateUserThread` to create our thread with the cpuContext and cpuHandle, We will fill in our Handle with `NtThread`...

Lets get the `ThreadContext` Now so we can get the registers...
```cpp
GetThreadContext(cpuHandle, &cpuContext);
std::cout << tContext.Rip << std::endl;
```
So now we have the `cpuContext` of the Thread which will give us all the current registers in the process suspended by the `CONTEXT` we created...

We will now change the `RIP/EIP` with the Address of our thread we will start (The Function We Will Call) and pass the context with the Fake Address we will give it in those registers, So while calling our actual function passed in with our void* `(ULONG64)thread` we will change the context to be our fake addr..
```cpp
#ifdef _WIN64 /* Win64 */
	tContext.Rip = (ULONG64)thread;
#else /* Win32 */
	tContext.Eip = (ULONG32)thread;
#endif
	tContext.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	SetThreadContext(cpuHandle, &cpuContext);

	std::cout << "[+] tContext Swapped, Resuming Thread..." << std::endl;
```
And then at the end of our code we will call `ResumeThread` to resume everything as normal..
```cpp
/* Resume Thread */
ResumeThread(cpuHandle);
```

# Execution
We will then execute our code by giving it a new thread to run with the fake `EIP/RIP` and then return null on our injected **DLL**...
```cpp
#include <Windows.h>
#include <iostream>	

#include "ultrahyde/hyde.h"

DWORD WINAPI ThreadFunction() {
	std::cout << "Thread Complete;" << std::endl;
	while (true) {
	}
	return 0;
}

int __stdcall DllMain(
	HMODULE hModule,
	std::uintptr_t reason,
	void* reserved
) {
	if (reason == 1) {
		// PRE-COMPILE //
		AllocConsole();
		FILE* fp;
		freopen_s(&fp, "CONOUT$", "w", stdout);
		hyde::ThreadLocation(ThreadFunction, hModule); /* Main Thread Function */
		return true;
	}
	return true;
}
```
So how this will work is our **DLL** Will be injected into the program, When its injected a thread will be automatically created to run our **DLL** Code, This thread will leak our **DLL** Memory Region and so we will pass it into our new function which will take the parameter **(ThreadFunction)** as a `VOID*` and It will run this as a new thread with a changed `EIP/RIP` Spoofed outside of the Original Threrad created as a New Thread, Once the New Thread is created with the swapped `EIP/RIP` It will then return outside of the function going back to the original `DllMain` Where it will `return true;` killing our **DLL's** Original Thread and using our New Thread on our actual code and actual function with a fake `EIP/RIP` For identification..

# Conclusion
This isn't a Full Proof Method of faking `EIP/RIP` Registers to spoof the Entry Point of your Thread, But it does work and is a pretty unique and common way of doing it..
