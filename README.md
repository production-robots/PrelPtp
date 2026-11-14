# PREL PTP time provider

> **Code signing.** From version 2.0.1, `PrelPtpSetup.exe` and the `PrelPtp.dll` it installs are signed by Production Robots Engineering Ltd (see [Code signing policy](#code-signing-policy)). Windows SmartScreen may still warn about the setup program while the signature is new (choose **More info**, then **Run anyway**), and because installing a time provider is also something malware does, Microsoft Defender may stop the installation; the code signing policy says what to do.

A PTP (IEEE 1588) time provider for the Windows Time service. It keeps a Windows PC's clock synchronised to a PTP grandmaster on the local network, to within a few microseconds when the network adapter supports hardware timestamps.

It comes as two programs:

- **PrelPtp.dll**, the time provider. The Windows Time service (w32time) loads it, and it gives w32time measurements of the clock's offset from the PTP master. w32time steers the clock.
- **PrelPtpSetup.exe**, which installs, configures and uninstalls it. It can also configure Microsoft's own PTP client (ptpprov.dll), which is part of Windows but is not well documented.

Contents: [Requirements](#requirements) · [Installing](#installing) · [The setup dialog](#the-setup-dialog) · [Hardware timestamps](#hardware-timestamps) · [Checking that it works](#checking-that-it-works) · [Uninstalling](#uninstalling) · [Registry settings](#registry-settings) · [Building from source](#building-from-source) · [Code signing policy](#code-signing-policy) · [License](#license)

## Requirements

- Windows 10 or later, or Windows Server, 64-bit (x64).
- Administrator rights to install and configure.
- A network adapter connected to a network with a PTP master: IEEE 1588-2008 (PTPv2) over UDP/IPv4 multicast, the transport used by the default profile and by SMPTE ST 2059-2. Layer 2 (Ethernet) transport and IPv6 are not supported.
- For hardware timestamps: Windows 11 or Windows Server 2022 or later, and an adapter whose driver supports them (see [Hardware timestamps](#hardware-timestamps)). Without them the provider uses software timestamps, which are less accurate.

**What accuracy to expect.** Measured on lab machines against a boundary clock:

| | Clock error once settled |
|---|---|
| Hardware timestamps (ConnectX-5, Windows Server 2022) | within about 1 µs of an independent measurement; offset typically within ±5 µs |
| Hardware timestamps (Intel I219-LM, Windows 11, through a non-PTP switch) | within ±1 µs on average |
| Software timestamps (ConnectX-5, Windows Server 2022) | about 12 µs ahead of the master, with a few µs of noise |
| Software timestamps (Intel I219-LM, Windows 11 workstation) | tens to over a hundred µs |

With software timestamps the error depends on the machine, adapter, driver and load. After a restart of the Windows Time service, the clock can take an hour or more to settle, because w32time re-learns the clock's frequency.

## Installing

1. Download `PrelPtpSetup.exe` from the [releases](../../releases).
2. Run it. It asks for administrator rights.
3. Choose **PREL PTP**, pick the adapter connected to the PTP network in the adapter list, and check the other settings (see below). The line at the bottom of the dialog says what OK will install.
4. Press **OK**.

OK does the following:

- copies PrelPtp.dll to `C:\Windows\System32`, and the setup program to `C:\Program Files\PrelPtp`, with a Start menu shortcut and an entry in Settings > Apps;
- saves the configuration in the registry;
- enables the selected time source in w32time and disables the others;
- adds an inbound firewall rule named "PTP" for the Windows Time service, UDP ports 319 and 320;
- sets the Windows Time service to start automatically, and restarts it.

To change the configuration later, run **PREL PTP** from the Start menu. The installed copy only configures; to update, run a newer downloaded `PrelPtpSetup.exe`. Updating over a newer version asks first.

**Recommended:** set w32time up for high accuracy by importing [Configuration/w32TimeHighAccuracy.reg](Configuration/w32TimeHighAccuracy.reg) and restarting the service (`Restart-Service w32time`). It makes w32time poll the provider every 64 s and update the clock more often. The setup program doesn't change these settings.

## The setup dialog

**Time provider.** The time source w32time uses. Only one is enabled at a time: two PTP providers can't share the PTP ports, and w32time would mix PTP and NTP.

- **PREL PTP**: this provider.
- **Microsoft PTP client**: Windows' own ptpprov.dll. Offered on Windows 11 and Windows Server 2022 (build 20348) and later, when ptpprov.dll is present. See [Microsoft's PTP client](#microsofts-ptp-client).
- **NTP client**: the Windows NTP client, as Windows has by default.
- **None**: no time source enabled by this program (for example, if another provider is in use).

PREL PTP stays installed whichever you choose, and its settings are kept, so you can switch back.

**PTP domain.** Any, or a domain number from 0 to 255. The list offers common ones: 0 (default profile), 127 (SMPTE ST 2059-2), 24 (ITU-T G.8275.1), 44 (ITU-T G.8275.2); you can also type a number. Messages in other domains are ignored. The adapter list shows which domains are heard.

**Grandmaster address.** 0.0.0.0 (or the **BMCA** button) means automatic: the provider follows the master chosen by the IEEE 1588 best master clock algorithm (BMCA) from the Announce messages, and fails over to the next one if it stops. Any other address pins the provider to the master at that address; messages from other masters are ignored.

> **Security:** the BMCA believes what Announce messages say, so any device on the network that claims to be a better clock will be followed. On a network you don't control, set the grandmaster address.

**Delay request interval.** How often the provider sends a Delay_Req to measure the path delay, on average, in milliseconds: 200 to 10000, default 1200 (1000 for the Microsoft PTP client).

**MS ptpprov parameters.** Only for the Microsoft PTP client; see below.

**Local adapter.** The adapter on the PTP network. The list shows physical Ethernet adapters with their IPv4 address and what PTP traffic is heard on each ("domain 127", "none", ...); hover over an adapter to see its masters and grandmaster, clock class, priority and steps removed. If no adapter is configured yet, the one with the best master is selected. The dialog listens for PTP while it is open, with a temporary firewall rule that is removed when it closes. For PREL PTP you must select an adapter. For MS ptpprov, the provider chooses an adapter. If MS ptpprov is active, the adapter list cannot show PTP status as the necessary ports are opened exclusively by ptpprov.

**OK** checks the entries first. Errors (for example no adapter selected, or an invalid address) must be corrected. Warnings (for example no PTP traffic in the chosen domain on that adapter) can be accepted.

**Release notes** shows the changes in this version, and **README** shows this document. Both open in the default web browser. **Uninstall** is described below.

### Microsoft's PTP client

Windows 11 and Windows Server 2022 include a PTP time provider, ptpprov.dll, registered in w32time as `PtpClient`. It uses hardware timestamps where available. Microsoft doesn't document its settings, so the setup program writes the values below, whose effect was established by experiment:

| Setting in the dialog | Registry value (`...\W32Time\TimeProviders\PtpClient`) |
|---|---|
| PTP domain | `DomainNumber` (Any is not available) |
| Grandmaster address | `PtpMasters` = the address. It is an allow-list: other masters are ignored. |
| Any master (0.0.0.0) | `PtpMasters` empty and `AllowAnyMaster` = 1 |
| Delay request interval | `DelayPollInterval` (ms; it behaves as a minimum interval) |
| Multicast receive | `EnableMulticastRx` |
| Multicast transmit (delay requests) | `EnableMulticastTx` = 1. Without it, Delay_Req are sent unicast to the master, which some masters don't answer. |
| Announce interval | `AnnounceInterval` (ms) |

Things to know about it:

- With "any master" on a machine that hears PTP on more than one adapter, it does not use the BMCA's choice and can pick the worse adapter. Set the grandmaster address in that case.
- It holds UDP 319 and 320 exclusively, so the setup dialog can't hear PTP traffic while it runs.
- Its diagnostics are in the event log under Applications and Services Logs > Microsoft > Windows > Time-Service-PTP-Provider > PTP-Operational, which is disabled by default.

## Hardware timestamps

Hardware timestamps are taken by the network adapter as the packet arrives or leaves, instead of by Windows afterwards, which removes most of the measurement error. PREL PTP uses them automatically when they are available, and falls back to software timestamps when they aren't.

They need:

- Windows 11 or Windows Server 2022 or later (Windows 10 can't deliver timestamps to a socket);
- an adapter and a current driver that support them, for example the NVIDIA (Mellanox) ConnectX-5 with WinOF-2, and some Intel adapters;
- the adapter's PTP hardware timestamp setting turned on. It is usually off by default. In Device Manager it is the advanced property "PTP Hardware Timestamp"; in PowerShell (elevated):

  ```powershell
  Get-NetAdapterAdvancedProperty -Name "<adapter>" -RegistryKeyword "*PtpHardwareTimestamp"
  Set-NetAdapterAdvancedProperty -Name "<adapter>" -RegistryKeyword "*PtpHardwareTimestamp" -RegistryValue 1
  ```

  Changing it restarts the adapter.

To see what an adapter offers, run `ts-probe.exe` (in the PrelPtp-debug download, or build it; see [Tools](#tools)). It lists each adapter's hardware and software timestamp capabilities, both supported and currently active.

The provider checks that the timestamps really arrive. If they don't, or if they stop, it switches to software timestamps and logs a warning; it then checks every few minutes whether they have come back, and switches back by itself.

**Known issue:** on the Intel I219-LM (driver e1d 12.19.2.66), hardware receive timestamps can stop after a few hours and stay stopped until the adapter is restarted, for example at the next reboot. The provider continues with software timestamps.

## Checking that it works

```powershell
w32tm /query /source            # should show "Prel PTP Client" (or the Microsoft PTP client's master)
w32tm /query /status /verbose   # last sync, phase offset
```


Strangely, `w32tm /query /source` requires elevation, `w32tm /query /status /verbose` does not.


The provider writes to the System event log, source **Time-Service**, with messages starting "Prel PTP provider": which adapter and address it listens on, the master it follows, whether it uses hardware or software timestamps, and problems such as the adapter not being ready, no PTP messages, messages only in other domains, or measurements stopping and resuming. To see the last half hour:

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Time-Service'; StartTime=(Get-Date).AddMinutes(-30)} |
  Sort-Object TimeCreated | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
```

## Uninstalling

Use **Uninstall** in the setup dialog, or Settings > Apps. It removes the provider, its configuration, the firewall rule (unless the Microsoft PTP client is selected, which needs it), the shortcut and the `C:\Program Files\PrelPtp` folder. It leaves the time source as it was, except when PREL PTP was the selected source: then it asks whether to enable the NTP client.

## Registry settings

The provider's configuration is in `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\PrelPtpProvider`. The setup program writes it; you don't normally need to edit it. Changes take effect when the Windows Time service restarts.

| Value | Type | Meaning |
|---|---|---|
| `AdapterName` | REG_SZ | The adapter's GUID, for example `{12345678-...}`. |
| `DomainNumber` | DWORD | 0-255. Absent: any domain. |
| `GrandmasterAddress` | REG_SZ | IPv4 address of the master to follow. Absent or 0.0.0.0: BMCA. |
| `DelayRequestInterval` | DWORD | Mean interval between delay requests, ms. Default 1200. |
| `FilterLength` | DWORD | Number of measurements averaged, 1-20. Default 20. |
| `TimestampMode` | DWORD | 0 or absent: hardware timestamps when available. 1: software timestamps only. Not shown in the dialog. |
| `DisableDelayRequest` | DWORD | 1: send no delay requests, so the path delay is not measured. An emergency override for special networks; logged as a warning at start-up. Not shown in the dialog, and removed when the dialog saves. |

`DllName`, `Enabled` and `InputProvider` are the standard w32time provider values.

## Building from source

You need:

- Visual Studio 2022 or later with the **Desktop development with C++** workload (it includes the Windows SDK);
- PowerShell 7 (`pwsh`; install it with `winget install Microsoft.PowerShell`). The build uses it to turn `README.md` and `RELEASE_NOTES.md` into the web pages that the setup program shows.

From a Developer PowerShell for Visual Studio:

```powershell
msbuild PrelPtp.sln /m /p:Configuration=Release /p:Platform=x64
```

or run `build.ps1` (`-Config Debug` for a debug build). The output is in `x64\Release` (or `x64\Debug`):

- `PrelPtp.dll`: the provider;
- `PrelPtpSetup.exe`: the setup program, with PrelPtp.dll from the same configuration, the README and the release notes built in;
- `PtpTests.dll`: the unit tests;
- `ts-probe.exe` and `ptp-driver.exe`: diagnostic tools (see [Tools](#tools)).

Run the unit tests with Visual Studio's Test Explorer, or:

```powershell
vstest.console.exe x64\Release\PtpTests.dll
```

To try a new build, run the built `PrelPtpSetup.exe`; it installs its own PrelPtp.dll. (A different build of the same version counts as an update.)

### Source layout

| Folder | Contents |
|---|---|
| `PrelPtp` | The provider DLL: the w32time time-provider interface (`PrelPtp.cpp`) and the client with its sockets and threads (`PtpClient.{h,cpp}`; there is a design note at the top of the header). |
| `PtpUtil` | Static library shared by all the projects: PTP messages and time conversion (`Ptp`), the BMCA (`Bmca`), message handling (`MessagePath`), the delay request/response exchange (`SyncRequest`), the measurement filter (`Filter`), timestamps (`Timestamp`), configuration and adapters (`Util`), time-provider selection (`TimeProviders`), the setup's PTP monitor (`PtpMonitor`) and validation (`Validation`). |
| `PrelPtpSetup` | The setup program: the dialog, installation (`Install`) and the firewall rule (`Firewall`). `MakeDocPages.ps1` turns the README and release notes into the web pages (in `DocPage.html`) that its buttons show. |
| `PtpTests` | Unit tests (Microsoft C++ Unit Test Framework). |
| `tools` | Diagnostic tools: `ts-probe` and `ptp-driver`. |
| `Configuration` | Optional w32time settings. |

### Tools

Two console programs for diagnosing and debugging. Each GitHub build saves them, with the symbol files, in its PrelPtp-debug download.

**ts-probe** shows which timestamps a machine can give PTP:

```
ts-probe.exe                            list adapters, their timestamp capabilities and a cross-timestamp
ts-probe.exe <ifIndex> [seconds] [--tx] also receive PTP event messages on that adapter and compare the
                                        socket timestamps with software timestamps; --tx also sends
                                        Delay_Req and reads their transmit timestamps
```

Find an adapter's ifIndex with `Get-NetAdapter`.

**ptp-driver** runs PrelPtp.dll outside the Windows Time service, in its place: it opens the provider, prints what it logs, asks it for a sample every 2 s and prints the offset, sends one network-change notification, then closes it and times the shutdown. It doesn't steer the clock. Use it to try a new build without installing it, or to debug the provider: run it under the debugger with a Debug build of PrelPtp.dll.

```
ptp-driver.exe [<path\to\PrelPtp.dll>] [seconds] [netchange-second]
```

The DLL defaults to PrelPtp.dll in the same folder, the run to 30 s, and the network change to half way (0 for none). The provider reads its configuration from the registry as usual, so run the setup program first. It can run while w32time is running PrelPtp, but not while Microsoft's PTP client is running, because that holds the PTP ports.

Conventions: every text file is UTF-8 with CRLF line endings (see `.gitattributes`). The `.rc` files say so to the resource compiler with `#pragma code_page(65001)`; if Visual Studio's resource editor ever saves one as UTF-16, convert it back. Release builds use the static C/C++ runtime (`/MT`), so the programs need no Visual C++ Redistributable. The version is set in `PrelPtpVersion.h`.

## Code signing policy

Releases from 2.0.1 on are code-signed: `PrelPtpSetup.exe` and the `PrelPtp.dll` it installs carry a signature from Production Robots Engineering Ltd, made with [Azure Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/). To check a file, open its Properties > Digital Signatures, or run `Get-AuthenticodeSignature <file>` in PowerShell.

- Only files built from this repository by its [GitHub Actions workflow](.github/workflows/build.yml) are signed: `PrelPtp.dll`, and `PrelPtpSetup.exe`, which contains it.
- Signing runs only in the workflow's `release` environment, which only the main branch and version tags can use, and Azure accepts signing requests only from that environment of this repository. No signing key or password is stored on GitHub.
- Every release is checked and published by hand.

Version 2.0.0 is not signed. Where application control (App Control for Business/WDAC, AppLocker) or endpoint protection blocks it, you can:

- allow the two files by hash: `PrelPtpSetup.exe`, and the installed `C:\Windows\System32\PrelPtp.dll` (for App Control, a hash rule made with `New-CIPolicyRule -Level Hash`);
- or [build them from source](#building-from-source) and sign them with your organisation's own code signing certificate. Sign `PrelPtp.dll` before `PrelPtpSetup.exe` is built, because the setup program embeds it and installs that copy.

Smart App Control can't make exceptions for individual unsigned programs; it has to be turned off.

**Microsoft Defender.** Registering a time provider is also a way for malware to make itself run inside a Windows service, so Microsoft Defender Antivirus may stop the setup program with the detection `Behavior:Win32/Persistence.Registry.TimeProvider.A` ("This program is dangerous and executes commands from an attacker"), and remove `PrelPtp.dll` and the provider's registry settings. If you are sure your copy of `PrelPtpSetup.exe` came from this repository's [releases](../../releases), you can allow it:

1. Open Windows Security > Virus & threat protection > Protection history, and open the detection.
2. Choose **Actions** > **Restore** (or **Allow on device**).
3. Run the setup program again and press **OK**.

Allowing it allows this detection on that PC for any program, not only PrelPtp; you can remove the exception later under Virus & threat protection > Allowed threats. Don't turn off real-time protection to get round it.

**Privacy:** this program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. The time provider exchanges PTP messages, as PTP requires, only on the network adapter chosen in the setup program, and the setup program listens for PTP traffic to show which adapters receive it. Neither sends anything to any other system.

## License

MIT; see [LICENSE](LICENSE). Copyright (c) 2019 Production Robots Engineering Ltd.
