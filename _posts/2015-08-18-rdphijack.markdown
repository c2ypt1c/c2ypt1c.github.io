---
layout: post
title:  MS15-082 RDP DLL Hijack Analysis
date:   2015-08-18 07:53:30
categories: jekyll update
---
Earlier this month, Microsoft issued an update for RDP [MS15-082](https://technet.microsoft.com/en-us/library/security/MS15-082) which addresses two vulnerabilities. One is caused by a DLL Hijacking flaw, in which RDP insecurely loads certain DLL files. This type of vulnerability hit the security scene in 2010, when Metasploit founder HD Moore released a detection tool specifically used for auditing DLL Hijacking vulnerabilities: [Exploiting DLL Hijacking Flaws](https://community.rapid7.com/community/metasploit/blog/2010/08/22/exploiting-dll-hijacking-flaws)

Fast-forward five years and we’re still seeing the effects of this class of vulnerability. The details surrounding CVE-2015-2473 are fairly scarce with Microsoft providing very limited information so we’ll need to dig deeper to see which DLL is affected and how it can be used to execute arbitrary code…

First, we need to determine which files were updated by the patch. [KB3075220](https://support.microsoft.com/en-us/kb/3075220) shows multiple files being updated, however, mstscax.dll has the most recent timestamp for Vista/2008 systems. Although my test system is running Windows 7, mstscax.dll still looks like a good place to start.

Using Diaphora, we can perform a binary diff against the new and old versions of mstscax.dll. The results show that multiple functions have changed.



![rdpdiff](/images/diffratio.JPG)

We see changes to functions dealing with encryption and certificates (no doubt from the other vulnerability accompanying MS15-082), however CDwmCoreAPI::Init seems to be the one we’re after.



![diffasm](/images/asmdiff.JPG)

Diffing the assembly, we see that the old mstscax.dll (highlighted in red) utilized the LoadLibraryW function on dwmcore.dll! This surely looks to be the vulnerable piece of code. Looking at the patched code (highlighted in green), a new subroutine is called on line 12 (call sub_2D32270E), in place of LoadLibraryW.



![sysdir](/images/getsysdir.JPG)

Digging into this new subroutine, we see a call to GetSystemDirectoryW, which is used to retrieve…you guessed it…the system directory. So, instead of loading dwmcore.dll from a potentially vulnerable location, this subroutine ensures that the system directory is used (such as C:\Windows\System32).

We now know that the DLL to hijack is dwmcore.dll, which mstscax.dll loads multiple functions from using GetProcAddress.



![funcload](/images/funcload.JPG)

DwmCoreAPI::Init handles all of the function loading, and once we compile a list (of all loaded functions from dwmcore.dll), we’re ready to write our malicious DLL file.

{% highlight cpp %}
#include <Windows.h>
#define DLLExport __declspec (dllexport)

int hijack()
{
	MessageBox(0, "DWMCORE IS VULNERABLE TO DLL HIJACKING!", "CVE-2015-2473", MB_OK);
	return 0;
}

DLLExport void MilChannel_CommitChannel() { hijack(); }
DLLExport void MilResource_SendCommand() { hijack(); }
DLLExport void MilTransport_Create() { hijack(); }
DLLExport void MilTransport_InitializeConnectionManager() { hijack(); }
DLLExport void MilCompositionEngine_InitializePartitionManager() { hijack(); }
DLLExport void MilCompositionEngine_DeinitializePartitionManager() { hijack(); }
DLLExport void MilTransport_ShutDownConnectionManager() { hijack(); }
DLLExport void MilTransport_DisconnectTransport() { hijack(); }
DLLExport void MilComposition_SyncFlush() { hijack(); }
DLLExport void MilResource_CreateOrAddRefOnChannel() { hijack(); }
DLLExport void MilChannel_SetNotificationWindow() { hijack(); }
DLLExport void MilConnection_CreateChannel() { hijack(); }
DLLExport void MilConnection_DestroyChannel() { hijack(); }
DLLExport void MilResource_ReleaseOnChannel() { hijack(); }
DLLExport void MilComposition_PeekNextMessage() { hijack(); }
DLLExport void MilTransport_Open() { hijack(); }
DLLExport void MilCrossThreadPacketTransport_Create() { hijack(); }
DLLExport void MilTransport_PostPacket() { hijack(); }
DLLExport void MilCommandTransport_Release() { hijack(); }
DLLExport void MilTransport_Close() { hijack(); }
DLLExport void MilConnectionManager_NotifyHostEvent() { hijack(); }
{% endhighlight %}

The trick here is that we’re redefining functions to call an arbitrary subroutine, hijack() in this case. So when RDP makes a call to any of these functions, hijack() will be executed. The next hurdle is to get RDP to follow a code path in which one of these functions is called.

Microsoft mentions “an attacker would first have to place a specially crafted DLL file in the target user’s current working directory and then convince the user to open a specially crafted RDP file.” So we know the vulnerability is triggered upon opening an RDP file.These can be created a few ways:



![rdpclient](/images/rdp_client_save.JPG)

Through the client




![remoteapp](/images/rdpappman.JPG)

Through RemoteApp Manager on Windows Server systems


Or manually…

The RDP file spec is so blatantly simple we can manually construct our own. A nice resource for this is [Overview of .rdp file settings](http://www.donkz.nl/files/rdpsettings.html) which lists keywords, data types, default values, etc…

At this point I hit a roadblock - simply placing our DLL in the same directory as the RDP file and opening it does not execute our code. However, I did some debugging and saw that the vulnerable LoadLibraryW code path is being hit, so I'm fairly certain it is loading it in properly. I will continue researching ways to get our malicious payload to execute, but the vulnerability seems to be related to dynamic virtual channels, which I know virtually (har har!)  nothing about. This link seems relevant [Remote Desktop Services Blog: Dynamic Virtual Channels](http://blogs.msdn.com/b/rds/archive/2007/09/20/dynamic-virtual-channels.aspx)
