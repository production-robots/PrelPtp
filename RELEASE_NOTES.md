# PREL PTP time provider: release notes

A PTP (IEEE 1588) time provider for the Windows Time service.

## 2.0.1

- `PrelPtpSetup.exe` and the `PrelPtp.dll` it installs are code-signed by Production Robots Engineering Ltd (see the README's Code signing policy). The programs are otherwise unchanged.
- README: what to do if Microsoft Defender stops the installation.

## 2.0.0

First open-source release.

### Time provider (PrelPtp.dll)

- Synchronises the Windows clock to a PTP grandmaster through the Windows Time service (w32time), using IEEE 1588-2008 (PTPv2) over UDP/IPv4 multicast: Sync, Follow_Up (one-step and two-step masters), Delay_Req and Delay_Resp, Announce.
- Master selection: by the IEEE 1588 best master clock algorithm (BMCA) from the Announce messages, or pinned to one grandmaster address.
- Domain selection: any domain, or one domain from 0 to 255. Messages from other domains are ignored, and the event log says so if they are the only ones received.
- Hardware timestamps: when the adapter supports them (Windows 11 or Windows Server 2022 and later, with the adapter's PTP hardware timestamp setting enabled), the provider uses the adapter's receive and transmit timestamps instead of software timestamps. It checks that they actually arrive. If they don't, or if they stop, it switches to software timestamps, says so in the event log, and switches back by itself if they return. It never restarts the adapter.
- Robust operation: starts even when the PTP adapter is not ready yet, and recovers by itself when the adapter is disabled, disconnected or gets a new address, without a restart of the Windows Time service. Out-of-date measurements are not given to the Windows Time service.
- Measurement filter: a moving average with a 5 ms outlier limit.
- The provider's clock identity is the standard EUI-64 form of the adapter's MAC address.

### Setup program (PrelPtpSetup.exe)

- One program installs, updates, configures and uninstalls. Run it from anywhere: when you press OK it installs or updates PrelPtp.dll (in System32) and itself (in C:\Program Files\PrelPtp), with a Start menu shortcut and an entry in Apps. The bottom line of the dialog says what will be installed or updated before you press OK. An update over a newer version asks first.
- Chooses the time source for the Windows Time service: PREL PTP, Microsoft's PTP client (ptpprov.dll, on Windows 11 and Windows Server 2022 and later), the Windows NTP client, or none. Only one is enabled at a time.
- Configures Microsoft's PTP client, whose registry values Microsoft does not document: domain, master (one address, or any master), delay request interval, multicast receive, multicast delay requests, announce interval.
- The adapter list shows which adapters receive PTP traffic, in which domains, and from which masters (tooltip). With no adapter configured, the one with the best master is selected.
- Entries are checked before they are saved: errors must be corrected; warnings (for example no PTP traffic in the chosen domain) can be accepted.
- Opens the firewall for PTP (UDP 319 and 320) for the Windows Time service.
- Uninstall (the button, or Apps) removes the provider, its configuration, the firewall rule, the shortcut and the C:\Program Files\PrelPtp folder. It leaves the time source as it was, except when PREL PTP was the only time source: then it asks whether to enable the NTP client.
- The Release notes and README buttons show these documents in the default web browser.

### Known issues

- Intel I219-LM (driver e1d 12.19.2.66, Windows 11): hardware receive timestamps can stop after a few hours and stay stopped until the adapter is restarted (for example at the next reboot). The provider continues with software timestamps.
- Configuration changes take effect when the Windows Time service restarts. The setup program restarts it when you press OK.

### Tested with

- Mellanox ConnectX-5 (WinOF-2 24.7) on Windows Server 2022: hardware and software timestamps.
- Intel I219-LM on Windows 11: hardware timestamps, with the known issue above.
