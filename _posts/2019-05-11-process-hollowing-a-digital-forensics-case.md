---
layout: post
title: "Process Hollowing: a digital forensics case"
description: "How to analyze a system infected with a malware that performs Process Hollowing, how to identify the hollowed process and how to extract the malicious image from memory for further analysis."
date: 2019-05-11
tags: malware, dfir
show_social: true
comments: true
---


<!--more-->

# Detecting Process Hollowing

In my [previous post]({{ site.baseurl }}{% post_url 2019-04-28-process-hollowing-a-reverse-engineering-case %}) I reverse engineered a malware sample that performs Process Hollowing.
In this post I describe how we can analyze a system infected with a malware that performs Process Hollowing. I'll be showing what techniques can be employed to identify the hollowed process by examining a live system or by analyzing a memory dump, and how to extract the malicious image from memory for further analysis.

# Esamining a live system

Let's pretend to be in front of an infected system.

## Inspecting the running processes

Depending on how stealth the malware is, we may or may not be able to spot the victimized process by simply looking at the Windows Task Manager. This is how it would look like:

![Running svchost.exe with Task Manager](/media/pma/lab-12-02/running-svchost-taskmanager.png)

The highlighted `svchost.exe` process (PID = 1136) looks suspicious because **it is running under a _normal_ user account** (`remuser`); this is not what we would normally expect, since legit `svchost.exe` processes usually run under administrative accounts like `SYSTEM`, `LOCAL SERVICE` or `NETWORK SERVICE`.

We can obtain more insight by using a tool like Process Explorer (or Process Hacker):

![Running svchost.exe with Process Explorer](/media/pma/lab-12-02/running-svchost-processexplorer.png)

We see here that the `svchost.exe` process with PID 1136 **does not have a parent process**, differently from all the other (legit) `svchost.exe` processes running on the system.

Malicious software often picks `svchost.exe` as the victim process. The `C:\Windows\System32\svchost.exe` is a Windows process used to host one or many Windows services. At any given time, multiple instances of `svchost.exe` may be running on a system (this is perfectly normal) and they should all be spawned by the `services.exe` process.

## Scanning the system with Hollows Hunter

[Hollows Hunter](https://github.com/hasherezade/hollows_hunter) is a tool (written by malware reasearcher Hasherezade) that scans all running processes on a system recognizing and dumping a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches). This tool is very handy during malware analysis as well as during digital forensics.

If we run Hollows Hunter on our infected system, the tool identifies the `svchost.exe` process having PID = 1136 as suspicious, and it dumps its image to a folder.

![Hollows Hunter](/media/pma/lab-12-02/hollowshunter.png)

Really straightforward!


# Analyzing a memory dump

So we got a memory dump of a machine infected with some malware that performs Process Hollowing: we have to investigate which is the victim process used by the malware to hide itself within.

> A live memory dump can be taken using tools like DumpIt or Belkasoft Live RAM Capturer.

We can analyze the memory dump with Volatility.

What are the signs to look for as indications that Process Hollowing has happened?


## Parent-child relationship

We can inspect the list of processes that were running on the target machine at the time the memory dump was taken, by running this command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pslist
```

![Volatility pslist output](/media/pma/lab-12-02/volatility-pslist.png)
_Volatility pslist output_

Inspecting the output of the `pslist` command, we see that all the `svchost.exe` processes, _but one_, have the same parent process (PPID = 576, i.e. `services.exe`); so the `svchost.exe` process with a different PPID (PID = 1136 and PPID = 160) is suspicious.

If we try to verify that PPID with this command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pslist -p 160
```
we get an error because that PID cannot be found: indeed the victim `svchost.exe` was created by the malware loader which terminated itself after performing Process Hollowing.

We can also display the same list of processes in a tree-like view using the `pstree` command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pstree
```

![Volatility pstree output](/media/pma/lab-12-02/volatility-pstree.png)
_Volatility pstree output_

That "orphan" `svchost.exe` (PID = 1136) appears suspicious.

> Some malware may choose to perform Process Hollowing against a different process (like `explorer.exe`), which normally runs without a parent process, thus making the malware stealthier.

## PEB and VAD discrepancies

The **Process Environment Block (PEB)** is a Windows kernel data structure (residing in user land) that contains information about each process, including the full path of the process image and its loaded modules.

The **Virtual Address Descriptor (VAD)** is a Windows kernel data structure (structured as a tree) that describes the memory regions allocated by each process, including the file image mapped to each region (if any).

Under normal circumstances, both the PEB and the VAD contain the same reference to the process image.

**When Process Hollowing occurs and the victim process image is unmapped from memory (via a call to `NtUnmapViewOfSection`), the reference to the original image disappears from the VAD. But that reference remains in the PEB.**

So if we suspect that a process was victim of Process Hollowing, we can check the PEB and the VAD kernel structures associated to that process and look for discrepancies.

The `dlllist` command displays the list of the DLLs loaded by a process, including the process executable itself; `dlllist` obtains this information from the PEB.

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem dlllist -p 1136
```

![Volatility dlllist output](/media/pma/lab-12-02/volatility-dlllist.png)
_Volatility dlllist output_

Now let's run the `ldrmodules` command, which displays the memory-mapped files referenced by the VAD.
As we suspected, the output does not contain any reference to the `svchost.exe` module:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem ldrmodules -p 1136
```

![Volatility ldrmodules output](/media/pma/lab-12-02/volatility-ldrmodules.png)
_Volatility ldrmodules output_

A reference to the process image missing in the VAD is an indication that Process Hollowing has occurred.

> Depending on the specific Process Hollowing technique used, there may be other types of discrepancies between the PEB and the VAD.

## Memory page permissions and VAD tag

During Process Hollowing, a malware needs to write into a new memory region that it allocated within the victim process; for this aim, the memory region is allocated with `PAGE_EXECUTE_READWRITE` permissions.

When an image is legitimately loaded into a memory region, the memory has a `PAGE_EXECUTE_WRITECOPY` protection. Differently, **a `PAGE_EXECUTE_READWRITE` protection is an indication that the image was _injected_ and not loaded in that memory region: this is a sign of Process Hollowing.**

**Another sign of Process Hollowing comes from the VAD tag being either `VadS` or `VadF`.**

The VAD tag defines the type of structure that is contained in each VAD node; a value equal to `VadS` or `VadF` indicates that the node does not contain a sub-structure, and this means that the node cannot map a file image - i.e., it does not contain any reference to the process image (see above).

The `malfind` command looks for signs of hidden or injected code like the ones described.

Let's run this command and inspect its output:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem malfind
```

![Volatility malfind output](/media/pma/lab-12-02/volatility-malfind.png)
_Volatility malfind output_

The process `svchost.exe` (PID 1136) is suspicious because the memory protection is `PAGE_EXECUTE_READWRITE` and the VAD tag is `VadS`.

> A careful malware author may change the memory permissions to `PAGE_EXECUTE_WRITECOPY` (via a call to `VirtualProtectEx`) after the program has finished writing into memory, thus making the malware stealthier.


## Fuzzy hashing



output of pslist | grep svchost:

![Volatility pslist svchost output](/media/pma/lab-12-02/volatility-pslist-svchost.png)


```
vol.py --profile WinXPSP3x86 -f infected-dump.mem procdump -p 776,840,920,992,1044,1136 -D dump
```

```
ssdeep -lrpa dump
```

![ssdeep output](/media/pma/lab-12-02/ssdeep.png)

sizes of dumped
fuzzyhash


## HollowFind

![Volatility hollowfind output](/media/pma/lab-12-02/volatility-hollowfind.png)



![Volatility psinfo legit output](/media/pma/lab-12-02/volatility-psinfo-legit.png)



https://github.com/monnappa22/HollowFind



# how to dump:


We can dump a suspect process from memory for further analysis using the `procdump` command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem procdump -p 1136
```

or with:

vaddump




<!--

 verificare gli ALT text delle immagini

 mostrare come appare il processo svchost in process explorer

 fare un cenno alla funzionalità di keylogging ?

 anticipare il post "Process Hollowing: a digital forensics case" che farà vedere come rilevare e analizzare un sistema infetto da un malware che ha eseguito un process hollowing:

 		- process explorer / process hacker (list vs tree view)
		- Volatility
		- Hollows Hunter / PE-sieve


-->


That's all!
