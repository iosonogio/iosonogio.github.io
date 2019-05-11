---
layout: post
title: "Process Hollowing: a digital forensics case"
description: "This post shows how to analyze a system infected with a malware that performs Process Hollowing, in order to identify the hollowed process and to extract the malicious image from memory for further analysis."
date: 2019-05-11
tags: dfir malware
show_social: true
comments: true
---

In my [previous post]({{ site.baseurl }}{% post_url 2019-04-28-process-hollowing-a-reverse-engineering-case %}) I reverse engineered a malware sample that performs Process Hollowing.

In this post I describe how we can analyze a system infected with a malware that performs Process Hollowing. I'll be showing which techniques can be employed to identify the hollowed process on a live system and in a memory dump, and how to extract the malicious image from memory for further analysis.

# Examining a live system

Let's pretend to be in front of the live infected system. 

## Inspecting the running processes

Depending on how stealth the malware is, we may or may not be able to spot the malicious process by simply looking at the list of running processes. This is how the Windows Task Manager would look like:

![Running svchost.exe with Task Manager](/media/pma/lab-12-02/running-svchost-taskmanager.png)
_Figure 1. Hollowed process in Windows Task Manager_

The highlighted `svchost.exe` process (PID = 1136) looks suspicious because **it is running under a _normal_ user account** (`remuser`); this is not what we would normally expect, since legit `svchost.exe` processes usually run under administrative accounts like `SYSTEM`, `LOCAL SERVICE` or `NETWORK SERVICE`.

We can obtain more insight using a tool like Process Explorer (or Process Hacker) that shows the parent-child relationship between any two processes:

![Running svchost.exe with Process Explorer](/media/pma/lab-12-02/running-svchost-processexplorer.png)
_Figure 2. Hollowed process in Process Explorer_

We see here that the `svchost.exe` process with PID 1136 **does not have a parent process**, differently from all the other (legit) `svchost.exe` processes running on the system.

> Malicious software often picks `svchost.exe` as the victim process. The `C:\Windows\System32\svchost.exe` is a Windows process used to host one or many Windows services. At any given time, multiple instances of `svchost.exe` may be running on a system (this is perfectly normal) and they should all be spawned by the `services.exe` process.

## Hunting with Hollows Hunter

[Hollows Hunter](https://github.com/hasherezade/hollows_hunter) is a tool (written by the malware reasearcher Hasherezade) that scans all running processes recognizing and dumping a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).

This tool is very handy during malware analysis as well as during digital forensic analysis.

If we run Hollows Hunter on our infected system, the tool identifies the `svchost.exe` process with PID = 1136 as suspicious and it dumps the process image to a folder along with a report of what it found.

![Hollows Hunter output](/media/pma/lab-12-02/hollowshunter.png)
_Figure 3. Output of Hollows Hunter_

Really straightforward!

# Analyzing a memory dump

We've got a memory dump of a machine infected with a malware that performs Process Hollowing (a memory dump of a live system can be taken using tools like DumpIt or Belkasoft Live RAM Capturer). Our task is to identify the victim process which the malware used to hide itself within.

> Memory analysis is extremely important not only during incident response but also during a malware analysis session (e.g. to help with identifing a rootkit or reverse engineering the final stage of an advanced malware that would otherwise be very hard to unpack).

Let's analyze the memory dump with Volatility and see what signs to look for as indications that Process Hollowing has happened.

## Parent-child relationship

We can inspect the list of processes that were running on the target machine at the time the memory dump was taken, by running this command (my dump was taken on a Windows XP SP3 x86 machine):

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pslist
```

![Volatility pslist output](/media/pma/lab-12-02/volatility-pslist.png)
_Figure 4. Output of Volatility `pslist`_

Inspecting the output of the `pslist` command, we see that all the `svchost.exe` processes, _but one_, have the same parent process (PPID = 576, i.e. `services.exe`); the `svchost.exe` process with a different PPID (PID = 1136 and PPID = 160) looks suspicious.

If we try to verify that PPID with this command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pslist -p 160
```

we get an error because this PID cannot be found. **Indeed the victim `svchost.exe` was created by the malware loader which terminated itself after performing Process Hollowing, so its parent process doesn't exist anymore.**

This is the same list filtered to show only the `svchost` processes. An interesting information to look for as well is the start time of the process: see how it differs?

![Volatility pslist output](/media/pma/lab-12-02/volatility-pslist-svchost.png)
_Figure 5. Output of Volatility `pslist` showing `svchost.exe` processes only_

We can also display the same list of processes in a tree-like view using the `pstree` command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem pstree
```

![Volatility pstree output](/media/pma/lab-12-02/volatility-pstree.png)
_Figure 6. Output of Volatility `pstree`_

That "orphan" `svchost.exe` (PID = 1136) appears suspicious.

> Some malware may perform Process Hollowing against a process (like `explorer.exe`) which normally runs _without_ a parent process, thus making the malware harder to detect.

## PEB and VAD discrepancies

Under normal circumstances, both the Process Environment Block (PEB) and the Virtual Address Descriptor (VAD) contain the same reference to the process image.

> The _Process Environment Block (PEB)_ is a Windows kernel data structure (residing in user land) that contains information about each process, including the full path of the process image and its loaded modules.

> The _Virtual Address Descriptor (VAD)_ is a Windows kernel data structure (structured as a tree) that describes the memory regions allocated by each process, including the file image mapped to each region (if any).

**When Process Hollowing occurs and the image of the victim process is unmapped from memory (via a call to `NtUnmapViewOfSection`), the reference to the original image disappears from the VAD. But that reference remains in the PEB.**

So if we suspect that a process was victim of Process Hollowing, we can check the PEB and the VAD kernel structures associated to that process and look for discrepancies.

The `dlllist` command displays the list of the DLLs loaded by a process, including the process executable itself; `dlllist` obtains this information from the PEB.

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem dlllist -p 1136
```

![Volatility dlllist output](/media/pma/lab-12-02/volatility-dlllist.png)
_Figure 7. Output of Volatility `dlllist` showing the path to the image of the suspicious `svchost.exe` process_

Now let's run the `ldrmodules` command, which displays the memory-mapped files referenced by the VAD of a process.

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem ldrmodules -p 1136
```

![Volatility ldrmodules output](/media/pma/lab-12-02/volatility-ldrmodules.png)
_Figure 8. Output of Volatility `ldrmodules`, no references to `svchost.exe`_

The output does not contain any reference to the `svchost.exe` module; when the reference to the process image is missing in the VAD, this is an indication that Process Hollowing has occurred.

> Depending on the specific Process Hollowing technique used, there may be other kinds of discrepancies between the PEB and the VAD.

## Memory page permissions and VAD tag

During Process Hollowing, a malware needs to write into a new memory region that it allocated within the victim process; for this aim, the memory region is allocated with `PAGE_EXECUTE_READWRITE` permissions. When an image is legitimately loaded into a memory region, the memory has a `PAGE_EXECUTE_WRITECOPY` protection. Differently, **a `PAGE_EXECUTE_READWRITE` protection is a symptom that the image was _injected_ and not loaded in that memory region: Process Hollowing may have happened.**

The VAD tag defines the type of structure that is contained in each VAD node; a value equal to `VadS` or `VadF` indicates that the node does _not_ contain a sub-structure, and this means that the node cannot map a file image - i.e., it does not contain any reference to the process image. So **if the VAD tag is either `VadS` or `VadF` then we have an indication of Process Hollowing.**

The `malfind` command looks for signs of hidden or injected code like the ones just described.

Let's run this command and inspect its output:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem malfind
```

![Volatility malfind output](/media/pma/lab-12-02/volatility-malfind.png)
_Figure 9. Output of Volatility `malfind`_

The process `svchost.exe` (PID 1136) is suspicious because the memory protection is `PAGE_EXECUTE_READWRITE` and the VAD tag is `VadS`. A dump of the first few bytes of the memory region is also shown.

> A careful malware author may change the memory permissions to `PAGE_EXECUTE_WRITECOPY` (via a call to `VirtualProtectEx`) after the program has finished writing into memory, thus making the malware stealthier.

## HollowFind

A Volatility plugin that is very handy for detecting different types of Process Hollowing techniques is [HollowFind](https://github.com/monnappa22/HollowFind) (written by the malware researcher Monnappa K A).

Let's try it:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem hollowfind
```

HollowFind identifies the `svchost.exe` process with PID 1136 as suspicious:

![Volatility hollowfind output](/media/pma/lab-12-02/volatility-hollowfind.png)
_Figure 10. Output of Volatility `hollowfind`_

This is how a _legit_ `svchost.exe` process would appear when we run the [`psinfo` Volatiliy plugin](https://github.com/monnappa22/Psinfo) (also written by the same author of HollowFind):

![Volatility psinfo legit output](/media/pma/lab-12-02/volatility-psinfo-legit.png)
_Figure 11. Output of Volatility `psinfo` showing the VAD and PEB information for a legit process_

In this case, both the VAD and the PEB contains similar information (including the image path), the VAD tag is Vad and the memory protection is as expected.

## Dumping a process

We can dump a suspicious process from memory for further analysis using the `procdump` command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem procdump -p 1136
```

## Fuzzy hashing

When we have multiple instances of a process, and one of them looks suspicious (like our hollowed `svchost.exe`), we can dump them all and compare their sizes and their _fuzzy hashes_.

Once we have the processes PIDs let's use the `procdump` command:

```
vol.py --profile WinXPSP3x86 -f infected-dump.mem procdump -p 776,840,920,992,1044,1136 -D dump
```

If we examine the dumped files we can notice that all but one have the same size on disk:

![Volatility pslist svchost output](/media/pma/lab-12-02/volatility-procdump.png)
_Figure 12. Dumped svchost.exe processes_

A powerful technique to identify _almost identical_ files, is **fuzzy hashing** also known as [Context Triggered Piecewise Hashes (CTPH)](http://dfrws.org/2006/proceedings/12-Kornblum.pdf).

> A common application of fuzzy hashing is to identify unknown variations of the same malware executable. Even though several samples may be different on a byte-by-byte basis (their hashes are different), their source code may be almost identical (their fuzzy hashes are the same!).

Here, we will use fuzzy hashing to detect the malicious `svchost.exe` image among those "almost identical" images of legit `svchost.exe` processes.

We can compute the fuzzy hashes using the [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) tool:

```
ssdeep -lrpa dump
```

![ssdeep output](/media/pma/lab-12-02/ssdeep.png)
_Figure 13. Output os ssdeep_

The number at the end of the line is a match score indicating how similar the files are; the higher the number, the more similar the files. The output of ssdeep shows that the `svchost.exe` process with PID 1136 differs from any other process with the same name (the score is zero).

That's all!
