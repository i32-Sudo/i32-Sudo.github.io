---
layout: post
title:  "_PEB / _TEB Exploitation for Module Link Manipulation using internally injected DLL (C++)"
---

###
I'll be showing some examples of exploitation of the (*Third*-**PE**-*Layer*) **_PEB** and **_TEB** (*Process Environment Block*) and (*Thread Environment Block*) created upon the (*Main-Thread*) Execution and Creation...  I'll also be explaining what the **_TEB** / **_PEB** Are and how they are used in a **PE**-*Executable* and how they may be useful to exploit and build as a structure in your main injected **DLL's**.

# _TEB (Thread Environment Block)
The Thread Environment Block is a thread’s user-mode representation. It has the highest amount of knowledge and control in a **PE**-*Executable* on the UserMode Level... It contains information about the Thread that is currently being Ran, a **_TEB** can be created for all threads being ran... The main structure of the **_TEB**
```cpp
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```
This is the main Structure of the **_TEB** inside of a **Thread** and contains memory based information along with the structure for our further explanation of the **_PEB**, Which we will explain... On the line;
```cpp
PPEB ProcessEnvironmentBlock;
```
You will see the **Data-Type** of `ProcessEnvironmentBlock;` is `PPEB`, This is because inside of the **_TEB** Structure includes the structure for the **_PEB** (**Process Environment Block**) Meaning you have to access the **_TEB** and Define the structure of the **_TEB** Before you define the structure of **_PEB**.

The **_TEB**  Is just the **Thread-Level-Block** That holds the information to the **_PEB** And other **Memory-Based-Areas**, You can google and research these functions as well for your own knowledge.
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm

The **_TEB**  is Apart of the **NTDLL** Structure and CodeBase and can't normally be accessed through **Exported- Functions** like **NTDLL** Would usually offer to manage inside a program... Instead we have to define the structure in our C++ Code and Load the **_TEB**.. We will explain this further when accessing the **_PEB**.

While the **_TEB** Can and usually is created on every thread the program is running, The **_PEB** is only 1 Structure apart of the Main Thread of the Process... And with every **_TEB** is just a Pointer to the main **_PEB** From the Main-Thread... And doesn't actually define a new **_PEB** with every **_TEB** Thread...

We will be using the **_TEB** to Access the **_PEB**..

# _PEB (Process Environment Block)
The **_PEB** (**Process Environment Block**) Holds information on the Main-Thread about the **PE-Executable** And can be accessed and modified by the program through typedef structures... It holds High-Level Information about the program, The Structure of the **_PEB** Looks like this...
```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```
This is the Primary Structure provided by Microsoft for Windows 10, 11 Latest... With some more Undocumented Data such as..
```cpp
     ULONG SystemReserved[1];
     ULONG SpareUlong;
     [PPEB_FREE_BLOCK](https://www.nirsoft.net/kernel_struct/vista/PEB_FREE_BLOCK.html) FreeList;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     VOID * * ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;
     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;
     [LARGE_INTEGER](https://www.nirsoft.net/kernel_struct/vista/LARGE_INTEGER.html) CriticalSectionTimeout;
     ULONG HeapSegmentReserve;
     ULONG HeapSegmentCommit;
     ULONG HeapDeCommitTotalFreeThreshold;
     ULONG HeapDeCommitFreeBlockThreshold;
     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     VOID * * ProcessHeaps;
     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;
     [PRTL_CRITICAL_SECTION](https://www.nirsoft.net/kernel_struct/vista/RTL_CRITICAL_SECTION.html) LoaderLock;
     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     WORD OSBuildNumber;
     WORD OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG ImageProcessAffinityMask;
     ULONG GdiHandleBuffer[34];
     PVOID PostProcessInitRoutine;
     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];
     ULONG SessionId;
     [ULARGE_INTEGER](https://www.nirsoft.net/kernel_struct/vista/ULARGE_INTEGER.html) AppCompatFlags;
     [ULARGE_INTEGER](https://www.nirsoft.net/kernel_struct/vista/ULARGE_INTEGER.html) AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;
     [UNICODE_STRING](https://www.nirsoft.net/kernel_struct/vista/UNICODE_STRING.html) CSDVersion;
     _ACTIVATION_CONTEXT_DATA * ActivationContextData;
     _ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
     _ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
     _ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;
     ULONG MinimumStackCommit;
     _FLS_CALLBACK_INFO * FlsCallback;
     [LIST_ENTRY](https://www.nirsoft.net/kernel_struct/vista/LIST_ENTRY.html) FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[4];
     ULONG FlsHighIndex;
     PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
} PEB, *PPEB;
```
### Full _PEB Documentation and UnDocumented DataTypes can be found at -> https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm

A lot of what the **_PEB** Does is keep track of everything happening in the Program such as **Loaded-DLL's**, **Loaded-Threads**, **Debugging Options**, **Program Param's**, And much more that may be undocumented...

The **_PEB** is much like the **_TEB** We already covered but this only runs once in the Main-Thread of the Program and holds a lot more information about the program that we may be able to exploit for our own potential gain... The **_TEB** only holds a Pointer to the **_PEB** in the Main-Process...

The **_PEB** is held within the **NTDLL** Structure so it may communicate with the Kernel...

One DataList of the **_PEB** That we will be looking at is `PPEB_LDR_DATA Ldr;` Which is another structure definition of `PPEB_LDR_DATA` with the name `Ldr;`... We will be covering the `PPEB_LDR_DATA` Structure as it contains most of the information about the **DLLs** Loaded in the program... The structure of `PPEB_LDR_DATA` Looks like this...
```cpp
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```
With `BYTE` and `PVOID` Being Memory Definitions, We are mostly Interested in `LIST_ENTRY` `InMemoryOrderModuleList` which contains data about Modules Loaded in the program... We will be primary Researching  this in our blog today and show how you can reverse a program for exploitation... Lets research the `LIST_ENTRY` Structure and see what we can use it for... The `LIST_ENTRY` Structure is viewed like this and once loaded looks like this in our program...
```cpp
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```
So we can see in the `LIST_ENTRY` there is 2 Structs called `_LIST_ENTRY *Flink;` and `_LIST_ENTRY *Blink;`, So we can tell based off the previous structure that we are looking inside of the `InMemoryOrderModuleList` Which holds all the information about every Module Loaded inside of the Memory, And how they are loaded is in a link-based-system, Meaning in goes in an order like so `Module1->Module2->Module3->Repeat->Module1.` And we can access these through their Flink and Blink... Bassicly a Flink and Blink is the beginning identifier and the ending identifier with the `Blink` Identifying the Start of the first of the module and the `Flink` Identifying the Beginning of the Next Module, Not the Entry-Point or the Base-Address but the next Structure for the Module... So say you want to access the Entry for a certain Module, You'd go through the `Flink/Blink` To get to that Module and load its structure..

Say we loop through the `Flink/Blink` Until we find a module we want, We can load its structure using the `_LDR_DATA_TABLE_ENTRY` Structure defined on the Microsoft Website for **winternl.h** where this is all taking place with **NTDLL**... The Structure of is like this
```cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```
This is how the Module Base Structure would look  for each Module Loaded, Now with the previous structure we looked at `_PEB_LDR_DATA` Its just the Array-Linker and allows us to identify each module, We can't access its name directly from `_PEB_LDR_DATA` but we can loop through each `Flink/Blink` in `_PEB_LDR_DATA` To find each Module and load its data based off  `_LDR_DATA_TABLE_ENTRY` as its just a `typedef struct`...

Looking in this we can see a few interesting data points such as `UNICODE_STRING FullDllName;` and `PVOID DllBase;` and also `PVOID EntryPoint;` and looking at the data types for these we can see one is a `PVOID` Meaning they are Pointer to Void Functions. (Addresses) Probably the Addresses to their Functions `DllBase/EntryPoint`, This is really interesting to us as say an Anti-Virus or an Anti-Cheat in a Game might loop through this same process and try to look at our DllBase and EntryPoint...

Well? We have just found our first vulnerability in a Program! And we can code our own DLL to exploit this.. We will show how to do this later, But note this down that with each Module Structure has information about the Modules DllBase, EntryPoint, and Name.. Along with the TimeDateStamp for the LoadTime of the Module...

Now those basic identifiers were giveaway's, But one thing you would want to keep an eye out for is the `LIST_ENTRY InMemoryOrderLinks;`, And if you examine the name `InMemoryOrderLinks` And pair that with the DataStructure `LIST_ENTRY`... You'll Realise that its actually the identifier for the `Flink/Blink` in that List/Array for that specific Module... What does this mean? That `LIST_ENTRY`Structure is the identifier for that module that puts the `FLINK/BLINK` Inside of `LIST_ENTRY InMemoryOrderModuleList;` that defines where our Module is in Memory/In the PE File... This is gonna come in real use to us...

Now with all our information gathered we are going to try and exploit these key data points, Specifically the `InMemoryOrderLinks` That defines our modules `Flink/Blink`... But we will also use the other data points such as `DllBase, EntryPoint, FullDllName, TimeDateStamp` to see if we can mask our traces better...

# Exploitation of the [InMemoryOrderModuleList]
With all the Information we gathered we will write a simple DLL that we will Inject and Hide, As our DLL is another Loaded Module.. To note we will be using a LoadLibraryA Injection Type to load our DLL so it is Loaded as a Regular DLL like any other, But we will use the Data we gathered before to Hide our Module in the process so it can't be discovered through the `InMemoryOrderModuleList`.

Something I didn't note earlier is that ***Every*** Module must be discovered through its `Flink/Blink` and every function has to go through the `InMemoryOrderModuleList` To identify the Module...

Lets access the **_PEB** Thorugh the **_TEB** in our **DLL**
```cpp
/* I'll be defining this struct called InternalStruct, This is my own
custom struct I'll be using to keep track of everything */

typedef struct internalStruct {
	uintptr_t RtlAcquirePebLock_addr;
	uintptr_t RtlReleasePebLock_addr;
	uintptr_t PEBAddr;
	PPEB_LDR_DATA PEBLdrAddr;
	ULONG newTime;
};
```
So. To access the **_TEB** and **_PEB** You need to call a Function inside of **ntdll.dll** called `RtlAcquirePebLock` Which will Unlock Access to the **_PEB** and the opposite Function `RtlReleasePebLock` Will Lock the **_PEB**. The **_PEB** By default is Locked to outside access and can only be managed by Kernel By Default... So we will be getting the Address of `RtlAcquirePebLock` and we will Call this in our DLL..
```cpp
void UnlinkModule(const char* ModuleName) {
	internalStruct PEBStructLoc;

	/* We will get the Address of PebLock and PebRelease */
	PEBStructLoc.RtlAcquirePebLock_addr = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAcquirePebLock"));
	PEBStructLoc.RtlReleasePebLock_addr = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlReleasePebLock"));
	
	/* We will then reinterpret_cast this into a void and __stdcall it to run the func at the address */
	reinterpret_cast<void(__stdcall*)(void)>(PEBStructLoc.RtlAcquirePebLock_addr)();
}
```
Cool, Now that we have unlocked the **_PEB** we can Load its structure...
```cpp
typedef struct internalStruct {
	uintptr_t RtlAcquirePebLock_addr;
	uintptr_t RtlReleasePebLock_addr;
	uintptr_t PEBAddr;
	PPEB_LDR_DATA PEBLdrAddr;
	ULONG newTime;
};

/* So the _PEB is Located in Memory register 0x60/0x30 for 64/32 intel/amd in the EPROCESS */
#ifdef _WIN64
	PEBStructLoc.PEBAddr = __readgsqword(0x60);
#else
	PEBStructLoc.PEBAddr = __readfsqword(0x30);
#endif

/* We will store these in our InternalStruct we made... */
```
Next we will get the `LDR` Directly in 1 Line by going through `PEB->LDR`
```cpp
PEBStructLoc.PEBLdrAddr = reinterpret_cast<PPEB_LDR_DATA>(reinterpret_cast<PPEB>(PEBStructLoc.PEBAddr)->Ldr);
```
Next we will get the `LIST_ENTRY` for `currentModuleEntry`, We will get the First Module in the `InLoadOrderModuleList` by its `Flink`.
```cpp
		PLIST_ENTRY currentModuleEntry = PEBStructLoc.PEBLdrAddr->InLoadOrderModuleList.Flink;
```
We will then implace a Loop to go through each Module in the currentModuleEntry
```cpp
/* We will loop through the CurrentModuleEntry is not equal to the last Module */
while (currentModuleEntry != &PEBStructLoc.PEBLdrAddr->InLoadOrderModuleList) {
	/* We will define the current moduleEntry and define the ModuleStructure */
	PLDR_MODULE moduleEntry = reinterpret_cast<PLDR_MODULE>(currentModuleEntry);
}
```
So now we have loaded the Module Structure in `moduleEntry`, We will build our structure and get the main name of the module...
```cpp
while  (currentModuleEntry !=  &PEBStructLoc.PEBLdrAddr->InLoadOrderModuleList)  {
			PLDR_MODULE moduleEntry =  reinterpret_cast<PLDR_MODULE>(currentModuleEntry);
			int bufferSize = WideCharToMultiByte(CP_ACP, 0, moduleEntry->BaseDllName.Buffer, moduleEntry->BaseDllName.Length / sizeof(wchar_t), nullptr, 0, nullptr, nullptr);
			char* narrowString = new char[bufferSize + 1];
			WideCharToMultiByte(CP_ACP, 0, moduleEntry->BaseDllName.Buffer, moduleEntry->BaseDllName.Length / sizeof(wchar_t), narrowString, bufferSize, nullptr, nullptr);
			narrowString[bufferSize] = '\0';

			if (strcmp(narrowString, ModuleName) == 0) {
				/* Our Module */
			}
			
			/* Flip to the Next Module in the Flink/Blink */
			currentModuleEntry = moduleEntry->InLoadOrderModuleList.Flink;
}

/* Re-Lock the _PEB so everything goes back to normal... */
reinterpret_cast<void(__stdcall*)(void)>(PEBStructLoc.RtlReleasePebLock_addr)();
```
So this code is a lot added, But we will explain it, Ther first section of the code defines the String for `BaseDllName` To see if the Name we Gave the function *The name of our DLL That has been Loaded...* Is the one that is currently loaded in `moduleEntry`.. We will use a `strcmp` to see if the string for our Module is the one inside of `moduleEntry->BaseDllName` and if so it will run the code inside of `/* Our Module */`...

Now it gets fun, Our ModuleLink Loop is done and we can loop through each Module inside of the `InLoadOrderModuleList` And we can find our Module now, We can use the information we gathered before to "change" it and define our module in other ways so when it goes to scan it, It gets different information then it should be, Because all standard functions have to go through the `InLoadOrderModuleList` to get the Module Info from a **DLL**..

One thing we will do is use `zeromem` on our `EntryPoint` and `BaseAddress` of our DLL, So say an AntiVirus or Anti-Cheat or Anti-DLL Program tries to scan our `EntryPoint/BaseAddress` of our DLL it will get no Memory but only `INT3` or `NULLMEM`... The way we can do this is like so... And I'll put up a structure of `moduleEntry ` to show..

```cpp
if  (strcmp(narrowString, ModuleName)  ==  0)  {
				ZeroMemory(&moduleEntry->BaseAddress, sizeof(moduleEntry->BaseAddress));
				ZeroMemory(&moduleEntry->EntryPoint, sizeof(moduleEntry->EntryPoint));
}
```
Cool, Now we ZeroMemory our BaseAddress and EntryPoint... Next we will spoof the TimeDateStamp AKA when our DLL Was Loaded with the previous DLL that was loaded when the program started.. Like so.
```cpp
if  (strcmp(narrowString, ModuleName)  ==  0)  {
				moduleEntry->TimeDateStamp = PEBStructLoc.newTime;

				ZeroMemory(&moduleEntry->BaseAddress, sizeof(moduleEntry->BaseAddress));
				ZeroMemory(&moduleEntry->EntryPoint, sizeof(moduleEntry->EntryPoint));
} else {
	PEBStructLoc.newTime = moduleEntry->TimeDateStamp;
}
```
How this works is we will save the newTime entry of the previous module and then save it in our custom `InternalStruct` where we have an entry defined called `newTime`... And then once its saved when our module is discovered we then change the `PEBStructLoc.newTime` inside of the module structure to give the time of the previous DLL because the previous DLL is a legit DLL loaded upon start of the program...

All of this is great, And we are using the information gathered to exploit and change it to make our DLL look more legit... Next we will fully unlink our DLL from the `InLoadOrderModuleList`, The way we will be doing this is my taking the previous `Blink` and the next `Flink` and matching them together..

How this works is we will take the previous modules `Flink` and make it our modules `Flink` and the next modules `Blink` and making that our `Blink`, So when it goes to scan for the next `Flink/Blink` it gets the Module over ours because we gave it the next `Blink` in front of our module.. And if it tries to go backwards to the previous module we give it the previous modules `Flink` so it never goes through our Module...

How we do this is shown here...

```cpp
if  (strcmp(narrowString, ModuleName)  ==  0)  {
				moduleEntry->TimeDateStamp = PEBStructLoc.newTime;

				ZeroMemory(&moduleEntry->BaseAddress, sizeof(moduleEntry->BaseAddress));
				ZeroMemory(&moduleEntry->EntryPoint, sizeof(moduleEntry->EntryPoint));

				/* Previous Module */
				moduleEntry->HashTableEntry.Blink->Flink = moduleEntry->HashTableEntry.Flink;
				moduleEntry->HashTableEntry.Flink->Blink = moduleEntry->HashTableEntry.Blink;

				/* Current Module (our module */
				currentModuleEntry->Blink->Flink = currentModuleEntry->Flink;
				currentModuleEntry->Flink->Blink = currentModuleEntry->Blink;
} else {
	PEBStructLoc.newTime = moduleEntry->TimeDateStamp;
}
```

And there you go, Our modules Flink/Blink has been swapped and our module has been unlinked, zeromem'd and changed time.. All methods we found based of the public structures provided by Microsoft...

Now at the end of our loop when we are all done we can Re-Lock the **_PEB** So we don't trigger any exceptions or any detections when it tries to check for modifications that shouldn't be happening...

We can do it like so..
```cpp
reinterpret_cast<void(__stdcall*)(void)>(PEBStructLoc.RtlReleasePebLock_addr)();
```

And after all of that we can pass in our Module Name like `pe.dll` into whatever function we defined...
`UnlinkModule("pe.dll");`

All Done...

# Conclusion
This was mainly a post to introduce people to the idea of being clever and unique when it comes to how you exploit programs and or modules, You don't have to be limited to what you know and all you have to do is research these things and do a bit of reverse engineering to come up with new ideas and new methods..

Thank you check my Github...
