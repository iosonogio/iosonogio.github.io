---
layout: post
title:  "How To Automatically Keep a Debian Server Up To Date"
date:   2017-07-25 10:30:00 +0200
categories: linux
tags: sysadmin apt debian
---
### Introduction

Linux Debian distribution relies on APT as a convenient and easy-to-use packaging system for managing software installations, upgrades and removals.

For a server administrator it would be nice to have some sort of automated process, on top of APT, for keeping a system constantly up to date, expecially with security patches.

This guide covers the automation aspects of software updates by addressing the following two needs:
- to be notified when installed packages have pending updates available;
- to have security updates automatically installed as soon as they get available, and hence to be notified of what packages have been upgraded.

## Prerequisites

This guide applies to Linux Debian and any Debian-based system like Ubuntu (it was tested on (version Debian 8.6 "Jessie").

## Finding Out What Changed

Let’s start with setting up a tool for obtaining information about what has changed in the packages that have upgrades available.

As a background information, we shall remind that each apt package usually ships with two files that contain some useful details about the package itself:
- a `changelog` file that summarizes recent changes made to the package;
- a `NEWS` file that describes significant changes about the package usually in a more user-oriented and descriptive style.

In order to display these details whenever an upgrade is to be executed, we can use the tool `apt-listchanges`. We also need this tool in conjuction with `apticron`, as we will see later, in order to receive details of what changes have been made to packages ready for update.

To install `apt-listchanges` just run:

```super_user
apt-get install apt-listchanges
```
By the way, this package should already be present on a fresh Debian 8.6 installation.

The configuration file is `/etc/apt/listchanges.conf`. The package can be configured by manually editing that file or by running the command:

```super_user
dpkg-reconfigure apt-listchanges
```

The configuration options are described in the man page. A common configuration setup could be the following:

```
[label /etc/apt/listchanges.conf]
[apt]
frontend=pager
email_address=root
confirm=1
which=news
```

The `frontend` option selects how information shall be displayed to the user (the `pager` value essentially means that the tool `less` will be used). The `email_address` option specifies the recipient we want the information be mailed to in case we choose the `mail` frontend. The `confirm` option determines whether a confirmation dialog is presented to the user after the information has been displayed and before proceeding with the upgrade. The `which` option selects which source of information among `changelogs`, `news` or `both` shall be displayed.

##Being Notified of Pending Updates

Next step, we want to be notified when installed packages have pending updates available. We can use the tool `apticron` for this job. Quoting from the Debian Handbook, `apticron` runs a script daily (via cron) which updates the list of available packages, and, if some installed packages are not in the latest available version, it downloads them and sends an email with the list of these packages along with the changes that have been made in the new versions.

Note that `apticron` needs the packages `apt-listchanges` (described above) in order to receive details about the changes, and `mailutils` in order to send out emails.

Let’s proceed with installing `apticron`, it's this simple:

```super_user
apt-get install apticron
```

During the process, the new cron task `/etc/cron.d/apticron` gets installed. Note that this is independent of the main APT cron task `/etc/cron.daily/apt`.

The relevant configuration file is `/etc/apticron/apticron.conf` which is fully commented. The default configuration should work fine in most situations, so we’ll just make sure that a valid email address is set:

```
[label /etc/apticron/apticron.conf]
EMAIL="root"
...
```

The following is an example of an email that we would receive from `apticron`:

```
[label An email sample from apticron]
apticron report [Mon, 09 Jan 2017 10:10:08 +0100]
========================================================================
apticron has detected that some packages need upgrading on:
    droptest
    [ OUR_IP_ADDRESS ]

The following packages are currently pending an upgrade:
    apt 1.0.9.8.4
    apt-utils 1.0.9.8.4
    libapt-inst1.5 1.0.9.8.4
    libapt-pkg4.12 1.0.9.8.4
    libxml2 2.9.1+dfsg1-5+deb8u4
========================================================================
Package Details:

Reading changelogs...
--- Changes for apt (apt apt-utils libapt-inst1.5 libapt-pkg4.12) ---
apt (1.0.9.8.4) jessie-security; urgency=high

 ...

========================================================================
You can perform the upgrade by issuing the command:
    apt-get dist-upgrade
as root on droptest

--
apticron
```

##Upgrading Automatically

As our final step, we want that packages be automatically upgraded as soon as updates are available. To this aim, we are going to use the tool `unattended-upgrade`, included in the package named `unattended-upgrades`. We can install it by running:

```super_user
apt-get install unattended-upgrades
```
By the way, this package should already be present on a fresh Debian 8.6 installation.

###Configuring Unattended Upgrades

The configuration file `/etc/apt/apt.conf.d/50unattended-upgrades` is fully commented. Let's see some of the relevant options.

The `Origins-Pattern` block controls which packages will be automatically upgraded. Since automatic unattended updates may be disruptive on a production server, we will limit them to security updates only. So let’s make sure that the line with the label `Debian-Security` in the `Origins-Pattern` block is _not_ commented out (it shouldn’t be by default):

```
[label /etc/apt/apt.conf.d/50unattended-upgrades]
Unattended-Upgrade::Origins-Pattern {
    // …
    "origin=Debian,codename=${distro_codename},label=<^>Debian-Security<^>";
};
```

Note that `${distro_codename}` gets expanded to the name of the current Debian release (e.g. “jessie”) as in `/etc/debian_version`.

If we want to blacklist some packages that shall be excluded from unattended upgrades, the relevant configuration block is `Package-Blacklist`.

In order to receive emails, let’s make sure to uncomment this line and set a valid email address:

```
[label /etc/apt/apt.conf.d/50unattended-upgrades]
Unattended-Upgrade::Mail "root";
```

We may want that unused dependencies be automatically removed after an upgrade, so let’s uncomment this line and set its value to `true`:

```
[label /etc/apt/apt.conf.d/50unattended-upgrades]
Unattended-Upgrade::Remove-Unused-Dependencies "true";
```

Lastly, `unattended-upgrade` is capable of automatically rebooting the system after an upgrade. This functionality is configured by the options `Automatic-Reboot` and `Automatic-Reboot-Time`. We should be careful to enable this functionality on a production server.

###Simulating execution

After we have installed and configured `unattended-upgrades`, we can simulate its execution by running this command:

```super_user
unattended-upgrade --dry-run --debug
```

The output of the command will show the allowed origins for unattended upgrades as set in the `Origins-Pattern`’s block. We can check them against the APT sources configured on our system by running:

```super_user
apt-cache policy
```

###Activating Unattended Upgrades

The installation process of `unattended-upgrades` does _not_ automatically enable the unattended upgrade functionality. To activate it, we need to properly configure `apt`. In fact, it is the apt cron task `/etc/cron.daily/apt` (that already comes with the `apt` package) that takes care of running `unattended-upgrade` accordingly to the proper configuration options.

Such options can be set in any file in `/etc/apt/apt.conf.d/`, since all files in this directory are parsed, in alphabetical order, when the apt cron task runs.

Conventionally, the options required to activate `unattended-upgrade` shall be placed in the file `/etc/apt/apt.conf.d/20auto-upgrades`. This file can be created manually by copying from `/usr/share/unattended-upgrades/20auto-upgrades` (recommended) or semi-automatically by running the command:

```super_user
dpkg-reconfigure -plow unattended-upgrades
```

The `20auto-upgrades` configuration file should contain (at least) the following two lines:

```
[label /etc/apt/apt.conf.d/20auto-upgrades]
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

The `Update-Package-Lists` option specifies the frequency (in days) at which the packages lists are refreshed. By setting it to **1** the packages lists will be updated at each run. By the way, this option does _not_ affect the behaviour of `apticron` which takes care of updating packages lists by itself.
The `Unattended-Upgrade` option will activate the `unattended-upgrade` functionality.


The following is an example of an email that we would receive from `unattended-upgrade`:

```
[label A sample email from unattended upgrade]
Unattended upgrade returned: True

Packages that were upgraded:
 apt apt-utils libapt-inst1.5 libapt-pkg4.12 libxml2

Unattended-upgrades log:
Initial blacklisted packages:
Initial whitelisted packages:
Starting unattended upgrades script
Allowed origins are: ['origin=Debian,codename=jessie,label=Debian-Security']
Packages that are auto removed: ''
Packages that will be upgraded: apt apt-utils libapt-inst1.5 libapt-pkg4.12 libxml2
Writing dpkg log to '/var/log/unattended-upgrades/unattended-upgrades-dpkg.log'
All upgrades installed
```


##Some more useful APT configuration options

Quoting from the Debian Handbook, this chapter describes some additional `APT::Periodic` configuration options used in the `/etc/cron.daily/apt` script that could be useful to us.

Configuration Option  | Description
------------- | -------------
`APT::Periodic::Download-Upgradeable-Packages`  | This option indicates the frequency (in days) for the downloading of the actual packages. This option is not needed by `apticron` nor by `unattended-upgrade` since they already perform this task by themselves.
`APT::Periodic::AutocleanInterval`  | This option controls how often (in days) obsolete packages are removed from the APT cache. Neither `apticron` nor `unattended-upgrade` need this option. We may want to set it so that the apt cache is kept at a reasonable size and we won't need to worry of housekeeping; we could place this option in a custom configuration file, say  `/etc/apt/apt.conf.d/99custom`.
`APT::Periodic::Verbose` | When set to (at least) **2**, the apt cron task `/etc/cron.daily/apt` will send us an email with details about its run. We could set this option in our custom configuration file `/etc/apt/apt.conf.d/99custom`.
`APT::Periodic::Enable` | This enables (when set to **1**) or disables (when set to **0**) the execution of the apt daily task `/etc/cron.daily/apt`. The default value is **1** so there is no need to explicitely set this option.

##Conclusions
In this tutorial we have covered how to set up an automated process for keeping a Debian system up to date. We installed and configured: `apt-listchanges` in order to know what has changed in the new packages versions; `apticron` in order to be notified when new versions of installed packages are available; and `unattended-upgrades` to automatically install packages updates.
