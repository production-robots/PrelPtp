// ts-probe: which timestamps does this machine offer for PTP?
//
// Lists each adapter's timestamp capabilities (hardware and software, supported and active) and takes
// two cross-timestamps (NIC clock against QPC). Run it to find out whether an adapter can give
// PrelPtp hardware timestamps.
//
// Usage:
//   ts-probe.exe                          list adapters, their timestamp capabilities and a cross-timestamp
//   ts-probe.exe <ifIndex> [seconds] [--tx]
//                                         also receive PTP event messages (port 319) on that adapter with
//                                         SIO_TIMESTAMPING, and compare each socket timestamp with the time
//                                         the receive call returned (the software timestamp method). --tx
//                                         also sends one Delay_Req per second (port number 2, so it never
//                                         matches the provider's own requests) and asks for its transmit
//                                         timestamp.
//
// Find an adapter's ifIndex with Get-NetAdapter.
//
// Windows has two generations of the capability API:
//   Windows 10 1809 .. 22H2 (RS5 layout): GetInterfaceHardwareTimestampCapabilities / GetInterfaceCurrentTimestampCapabilities
//   Server 2022 / Windows 11 (FE layout): GetInterfaceSupportedTimestampCapabilities / GetInterfaceActiveTimestampCapabilities
// Both are looked up at run time, with private copies of each layout. Socket timestamping
// (SIO_TIMESTAMPING, SO_TIMESTAMP) is only declared for FE and later; the probe tries it anyway.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifndef SIO_TIMESTAMPING
#define SIO_TIMESTAMPING _WSAIOW(IOC_VENDOR, 235)
typedef struct _TIMESTAMPING_CONFIG { ULONG Flags; USHORT TxTimestampsBuffered; } TIMESTAMPING_CONFIG;
#define TIMESTAMPING_FLAG_RX 0x1
#define TIMESTAMPING_FLAG_TX 0x2
#define SO_TIMESTAMP 0x300A
#define SO_TIMESTAMP_ID 0x300B
#define SIO_GET_TX_TIMESTAMP _WSAIOW(IOC_VENDOR, 234)
#endif

// --- FE layout (Server 2022 / Windows 11) ---
struct FeHw { BOOLEAN v4EvRx, v4AllRx, v4EvTx, v4AllTx, v6EvRx, v6AllRx, v6EvTx, v6AllTx, AllRx, AllTx, TaggedTx; };
struct FeSw { BOOLEAN AllRx, AllTx, TaggedTx; };
struct FeCaps { ULONG64 HwClockHz; BOOLEAN CrossTs; FeHw Hw; FeSw Sw; };
struct FeCross { ULONG64 Sys1, Hw, Sys2; };

// --- RS5 layout (Windows 10 1809 .. 22H2) ---
struct Rs5Flags { BOOLEAN v4EvRxHw, v4AllRxHw, v4EvTxHw, v4AllTxHw, v6EvRxHw, v6AllRxHw, v6EvTxHw, v6AllTxHw,
                  AllRxHw, AllTxHw, TaggedTxHw, AllRxSw, AllTxSw, TaggedTxSw; };
struct Rs5Caps { ULONG Version; ULONG64 HwClockHz; BOOLEAN CrossTs; ULONG64 Res1, Res2; Rs5Flags F; };
struct Rs5Cross { ULONG Version; ULONG Flags; ULONG64 Sys1, Hw, Sys2; };

typedef DWORD (WINAPI* CapsFn)(const NET_LUID*, void*);
typedef DWORD (WINAPI* CrossFn)(const NET_LUID*, void*);

// Normalised view used by the rest of the probe.
struct Caps {
  bool ok = false;
  DWORD err = 0;
  ULONG64 hwHz = 0;
  bool cross = false;
  bool v4EvRx = false, v4AllRx = false, v4EvTx = false, v4AllTx = false;
  bool hwAllRx = false, hwAllTx = false, hwTaggedTx = false;
  bool swAllRx = false, swAllTx = false, swTaggedTx = false;
};

static bool g_fe = false;
static CapsFn g_supported = nullptr, g_active = nullptr;
static CrossFn g_cross = nullptr;
static LARGE_INTEGER g_qpf;

static void LoadApis()
{
  HMODULE h = LoadLibraryW(L"iphlpapi.dll");
  if (!h) return;
  g_supported = (CapsFn)GetProcAddress(h, "GetInterfaceSupportedTimestampCapabilities");
  g_active = (CapsFn)GetProcAddress(h, "GetInterfaceActiveTimestampCapabilities");
  if (g_supported && g_active) {
    g_fe = true;
  } else {
    g_supported = (CapsFn)GetProcAddress(h, "GetInterfaceHardwareTimestampCapabilities");
    g_active = (CapsFn)GetProcAddress(h, "GetInterfaceCurrentTimestampCapabilities");
  }
  g_cross = (CrossFn)GetProcAddress(h, "CaptureInterfaceHardwareCrossTimestamp");
}

static Caps QueryCaps(CapsFn fn, const NET_LUID& luid)
{
  Caps c;
  if (!fn) { c.err = ERROR_PROC_NOT_FOUND; return c; }
  if (g_fe) {
    FeCaps f = {};
    c.err = fn(&luid, &f);
    if (c.err) return c;
    c.ok = true; c.hwHz = f.HwClockHz; c.cross = f.CrossTs != 0;
    c.v4EvRx = f.Hw.v4EvRx; c.v4AllRx = f.Hw.v4AllRx; c.v4EvTx = f.Hw.v4EvTx; c.v4AllTx = f.Hw.v4AllTx;
    c.hwAllRx = f.Hw.AllRx; c.hwAllTx = f.Hw.AllTx; c.hwTaggedTx = f.Hw.TaggedTx;
    c.swAllRx = f.Sw.AllRx; c.swAllTx = f.Sw.AllTx; c.swTaggedTx = f.Sw.TaggedTx;
  } else {
    Rs5Caps r = {};
    r.Version = 1;
    c.err = fn(&luid, &r);
    if (c.err) return c;
    c.ok = true; c.hwHz = r.HwClockHz; c.cross = r.CrossTs != 0;
    c.v4EvRx = r.F.v4EvRxHw; c.v4AllRx = r.F.v4AllRxHw; c.v4EvTx = r.F.v4EvTxHw; c.v4AllTx = r.F.v4AllTxHw;
    c.hwAllRx = r.F.AllRxHw; c.hwAllTx = r.F.AllTxHw; c.hwTaggedTx = r.F.TaggedTxHw;
    c.swAllRx = r.F.AllRxSw; c.swAllTx = r.F.AllTxSw; c.swTaggedTx = r.F.TaggedTxSw;
  }
  return c;
}

static void PrintCaps(const char* label, const Caps& c)
{
  if (!c.ok) { printf("    %-9s error %lu\n", label, c.err); return; }
  printf("    %-9s hw clock %llu Hz, cross-timestamp %s\n", label, c.hwHz, c.cross ? "yes" : "no");
  printf("              hw PTPv2/UDPv4: event rx %d, all rx %d, event tx %d, all tx %d\n", c.v4EvRx, c.v4AllRx, c.v4EvTx, c.v4AllTx);
  printf("              hw all rx %d, all tx %d, tagged tx %d   sw all rx %d, all tx %d, tagged tx %d\n",
         c.hwAllRx, c.hwAllTx, c.hwTaggedTx, c.swAllRx, c.swAllTx, c.swTaggedTx);
}

struct Cross { bool ok = false; DWORD err = 0; ULONG64 sys1 = 0, hw = 0, sys2 = 0; };

static Cross CaptureCross(const NET_LUID& luid)
{
  Cross x;
  if (!g_cross) { x.err = ERROR_PROC_NOT_FOUND; return x; }
  if (g_fe) {
    FeCross f = {};
    x.err = g_cross(&luid, &f);
    if (!x.err) { x.ok = true; x.sys1 = f.Sys1; x.hw = f.Hw; x.sys2 = f.Sys2; }
  } else {
    Rs5Cross r = {};
    r.Version = 1;
    x.err = g_cross(&luid, &r);
    if (!x.err) { x.ok = true; x.sys1 = r.Sys1; x.hw = r.Hw; x.sys2 = r.Sys2; }
  }
  return x;
}

struct Adapter { ULONG ifIndex; NET_LUID luid; wchar_t name[128]; wchar_t desc[256]; in_addr addr; BYTE mac[8]; ULONG macLen; bool up; };

static std::vector<Adapter> ListAdapters()
{
  std::vector<Adapter> out;
  ULONG size = 64 * 1024;
  std::vector<BYTE> buf(size);
  if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                           nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size) != NO_ERROR)
    return out;
  for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    Adapter d = {};
    d.ifIndex = a->IfIndex;
    d.luid = a->Luid;
    wcsncpy_s(d.name, a->FriendlyName, _TRUNCATE);
    wcsncpy_s(d.desc, a->Description, _TRUNCATE);
    d.up = a->OperStatus == IfOperStatusUp;
    d.macLen = a->PhysicalAddressLength < 8 ? a->PhysicalAddressLength : 8;
    memcpy(d.mac, a->PhysicalAddress, d.macLen);
    for (auto* u = a->FirstUnicastAddress; u; u = u->Next)
      if (u->Address.lpSockaddr->sa_family == AF_INET) { d.addr = ((sockaddr_in*)u->Address.lpSockaddr)->sin_addr; break; }
    out.push_back(d);
  }
  return out;
}

static double QpcToUs(LONGLONG ticks) { return ticks * 1e6 / (double)g_qpf.QuadPart; }

// Map a NIC clock value to QPC through a cross-timestamp (midpoint of the two system reads).
static double HwToQpc(ULONG64 hw, const Cross& x, ULONG64 hwHz)
{
  double mid = (x.sys1 + x.sys2) / 2.0;
  return mid + ((double)(LONGLONG)(hw - x.hw)) * (double)g_qpf.QuadPart / (double)hwHz;
}

struct Stats {
  int n = 0; double sum = 0, sum2 = 0, mn = 1e300, mx = -1e300;
  void Add(double v) { n++; sum += v; sum2 += v * v; if (v < mn) mn = v; if (v > mx) mx = v; }
  void Print(const char* label) const {
    if (!n) { printf("  %-44s no data\n", label); return; }
    double mean = sum / n, sd = sqrt(fmax(0.0, sum2 / n - mean * mean));
    printf("  %-44s n %4d  mean %10.2f  sd %8.2f  min %10.2f  max %10.2f us\n", label, n, mean, sd, mn, mx);
  }
};

static const char* MsgName(int t)
{
  switch (t) { case 0: return "Sync"; case 1: return "Delay_Req"; case 2: return "Pdelay_Req"; case 3: return "Pdelay_Resp"; default: return "other"; }
}

static int SocketTest(const Adapter& ad, const Caps& active, int seconds, bool tx)
{
  if (ad.addr.s_addr == 0) { printf("Adapter has no IPv4 address\n"); return 1; }
  SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) { printf("socket: %d\n", WSAGetLastError()); return 1; }
  BOOL one = TRUE;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
  sockaddr_in local = {};
  local.sin_family = AF_INET;
  local.sin_port = htons(319);
  local.sin_addr = ad.addr;
  if (bind(s, (sockaddr*)&local, sizeof(local))) { printf("bind: %d\n", WSAGetLastError()); return 1; }
  ip_mreq mreq = {};
  inet_pton(AF_INET, "224.0.1.129", &mreq.imr_multiaddr);
  mreq.imr_interface = ad.addr;
  if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq))) { printf("IP_ADD_MEMBERSHIP: %d\n", WSAGetLastError()); return 1; }
  setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char*)&ad.addr, sizeof(ad.addr));
  DWORD rcvto = 250;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvto, sizeof(rcvto));

  TIMESTAMPING_CONFIG cfg = {};
  cfg.Flags = TIMESTAMPING_FLAG_RX | (tx ? TIMESTAMPING_FLAG_TX : 0);
  cfg.TxTimestampsBuffered = 4;
  DWORD bytes = 0;
  if (WSAIoctl(s, SIO_TIMESTAMPING, &cfg, sizeof(cfg), nullptr, 0, &bytes, nullptr, nullptr)) {
    printf("SIO_TIMESTAMPING: error %d (socket timestamping not available on this Windows build)\n", WSAGetLastError());
  } else {
    printf("SIO_TIMESTAMPING: enabled (rx%s)\n", tx ? " + tx" : "");
  }

  GUID gRecv = WSAID_WSARECVMSG, gSend = WSAID_WSASENDMSG;
  LPFN_WSARECVMSG pRecv = nullptr;
  LPFN_WSASENDMSG pSend = nullptr;
  WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &gRecv, sizeof(gRecv), &pRecv, sizeof(pRecv), &bytes, nullptr, nullptr);
  WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &gSend, sizeof(gSend), &pSend, sizeof(pSend), &bytes, nullptr, nullptr);
  if (!pRecv || !pSend) { printf("WSARecvMsg/WSASendMsg not available\n"); return 1; }

  // Interpretation of the socket timestamp: with hardware rx timestamps active it is NIC clock ticks,
  // otherwise QPC ticks. Hardware values are mapped to QPC through a cross-timestamp taken each second.
  bool hwRx = active.ok && (active.v4EvRx || active.v4AllRx || active.hwAllRx);
  bool hwTx = active.ok && (active.v4EvTx || active.v4AllTx || active.hwAllTx || active.hwTaggedTx);
  printf("Socket timestamps interpreted as %s on receive, %s on transmit\n\n", hwRx ? "NIC clock" : "QPC", hwTx ? "NIC clock" : "QPC");
  Cross x = CaptureCross(ad.luid);

  Stats latency;       // wake - socket timestamp
  Stats intWake, intTs; // Sync arrival interval, measured both ways
  double lastWake = 0, lastTs = 0;
  int msgs = 0, withTs = 0, printed = 0;
  BYTE delayReq[44] = {};
  BYTE domain = 0;
  USHORT txSeq = 0;
  int txSent = 0, txGot = 0;
  Stats txLatency;     // socket tx timestamp - QPC before send

  LARGE_INTEGER start, now, lastTx, lastCross;
  QueryPerformanceCounter(&start);
  lastTx = lastCross = start;
  for (;;) {
    QueryPerformanceCounter(&now);
    if (now.QuadPart - start.QuadPart > (LONGLONG)seconds * g_qpf.QuadPart) break;
    if (now.QuadPart - lastCross.QuadPart > g_qpf.QuadPart) { x = CaptureCross(ad.luid); lastCross = now; }

    if (tx && now.QuadPart - lastTx.QuadPart > g_qpf.QuadPart && ad.macLen == 6) {
      lastTx = now;
      memset(delayReq, 0, sizeof(delayReq));
      delayReq[0] = 0x01; delayReq[1] = 0x02; delayReq[3] = 44; delayReq[4] = domain;
      BYTE* id = delayReq + 20;
      id[0] = ad.mac[0]; id[1] = ad.mac[1]; id[2] = ad.mac[2]; id[3] = 0xFF; id[4] = 0xFE;
      id[5] = ad.mac[3]; id[6] = ad.mac[4]; id[7] = ad.mac[5]; id[8] = 0; id[9] = 2;
      delayReq[30] = (BYTE)(txSeq >> 8); delayReq[31] = (BYTE)txSeq; delayReq[32] = 1; delayReq[33] = 0x7F;
      sockaddr_in to = {};
      to.sin_family = AF_INET; to.sin_port = htons(319);
      to.sin_addr = mreq.imr_multiaddr;
      UINT32 tsId = txSeq;
      char ctl[WSA_CMSG_SPACE(sizeof(UINT32))] = {};
      WSACMSGHDR* cm = (WSACMSGHDR*)ctl;
      cm->cmsg_len = WSA_CMSG_LEN(sizeof(UINT32));
      cm->cmsg_level = SOL_SOCKET;
      cm->cmsg_type = SO_TIMESTAMP_ID;
      memcpy(WSA_CMSG_DATA(cm), &tsId, sizeof(tsId));
      WSABUF wb = { sizeof(delayReq), (char*)delayReq };
      WSAMSG m = {};
      m.name = (sockaddr*)&to; m.namelen = sizeof(to);
      m.lpBuffers = &wb; m.dwBufferCount = 1;
      m.Control.buf = ctl; m.Control.len = sizeof(ctl);
      LARGE_INTEGER before;
      QueryPerformanceCounter(&before);
      DWORD sent = 0;
      if (pSend(s, &m, 0, &sent, nullptr, nullptr)) {
        printf("WSASendMsg: %d\n", WSAGetLastError());
      } else {
        txSent++;
        UINT64 txTs = 0;
        int err = WSAEWOULDBLOCK;
        for (int i = 0; i < 50 && err == WSAEWOULDBLOCK; i++) {
          if (WSAIoctl(s, SIO_GET_TX_TIMESTAMP, &tsId, sizeof(tsId), &txTs, sizeof(txTs), &bytes, nullptr, nullptr) == 0) err = 0;
          else { err = WSAGetLastError(); if (err == WSAEWOULDBLOCK) Sleep(2); }
        }
        if (err) {
          printf("tx seq %u: no transmit timestamp (error %d)\n", txSeq, err);
        } else {
          txGot++;
          double tsQpc = hwTx && x.ok && active.hwHz ? HwToQpc(txTs, x, active.hwHz) : (double)txTs;
          double us = QpcToUs((LONGLONG)(tsQpc - before.QuadPart));
          txLatency.Add(us);
          printf("tx seq %u: timestamp %llu, %.2f us after the send call started\n", txSeq, txTs, us);
        }
      }
      txSeq++;
    }

    BYTE buf[256];
    char ctl[256];
    sockaddr_in from = {};
    WSABUF wb = { sizeof(buf), (char*)buf };
    WSAMSG m = {};
    m.name = (sockaddr*)&from; m.namelen = sizeof(from);
    m.lpBuffers = &wb; m.dwBufferCount = 1;
    m.Control.buf = ctl; m.Control.len = sizeof(ctl);
    DWORD got = 0;
    if (pRecv(s, &m, &got, nullptr, nullptr)) {
      int e = WSAGetLastError();
      if (e != WSAETIMEDOUT) { printf("WSARecvMsg: %d\n", e); break; }
      continue;
    }
    LARGE_INTEGER wake;
    QueryPerformanceCounter(&wake);   // the software method: time taken when the receive returns
    if (got < 34) continue;
    msgs++;
    int type = buf[0] & 0x0F;
    USHORT seq = (USHORT)((buf[30] << 8) | buf[31]);
    if (type == 0) domain = buf[4];
    bool haveTs = false;
    UINT64 ts = 0;
    for (WSACMSGHDR* cm = WSA_CMSG_FIRSTHDR(&m); cm; cm = WSA_CMSG_NXTHDR(&m, cm)) {
      if (cm->cmsg_type == SO_TIMESTAMP && cm->cmsg_len >= WSA_CMSG_LEN(sizeof(UINT64))) {
        memcpy(&ts, WSA_CMSG_DATA(cm), sizeof(ts));
        // Server 2022 attaches SO_TIMESTAMP with value 0 when no timestamping is active.
        haveTs = ts != 0;
      } else {
        printf("  (control message level %d type %d)\n", cm->cmsg_level, cm->cmsg_type);
      }
    }
    char src[32];
    inet_ntop(AF_INET, &from.sin_addr, src, sizeof(src));
    double tsQpc = 0, lat = 0;
    if (haveTs) {
      withTs++;
      tsQpc = hwRx && x.ok && active.hwHz ? HwToQpc(ts, x, active.hwHz) : (double)ts;
      lat = QpcToUs((LONGLONG)(wake.QuadPart - tsQpc));
      if (type == 0) latency.Add(lat);
    }
    if (type == 0) {
      double w = QpcToUs(wake.QuadPart);
      if (lastWake) intWake.Add(w - lastWake);
      lastWake = w;
      if (haveTs) {
        double t = QpcToUs((LONGLONG)tsQpc);
        if (lastTs) intTs.Add(t - lastTs);
        lastTs = t;
      }
    }
    if (printed < 20) {
      printed++;
      if (haveTs)
        printf("%-11s seq %5u from %-15s domain %3u  ts %llu  wake - ts %.2f us\n", MsgName(type), seq, src, buf[4], ts, lat);
      else
        printf("%-11s seq %5u from %-15s domain %3u  no socket timestamp\n", MsgName(type), seq, src, buf[4]);
    }
  }
  closesocket(s);

  printf("\n%d event messages in %d s, %d with a socket timestamp\n", msgs, seconds, withTs);
  latency.Print("Sync: receive returned - socket timestamp");
  intWake.Print("Sync interval, by receive-return time");
  intTs.Print("Sync interval, by socket timestamp");
  if (tx) {
    printf("Delay_Req: %d sent, %d transmit timestamps\n", txSent, txGot);
    txLatency.Print("Delay_Req: tx timestamp - before send");
  }
  return 0;
}

int main(int argc, char** argv)
{
  QueryPerformanceFrequency(&g_qpf);
  LoadApis();
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);

  printf("Capability API: %s\n", g_supported ? (g_fe ? "FE (Supported/Active)" : "RS5 (Hardware/Current)") : "not present");
  printf("Cross-timestamp API: %s\n", g_cross ? "present" : "not present");
  printf("QPC frequency: %lld Hz\n\n", g_qpf.QuadPart);

  ULONG want = argc > 1 ? strtoul(argv[1], nullptr, 10) : 0;
  int seconds = argc > 2 ? atoi(argv[2]) : 10;
  bool tx = false;
  for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--tx")) tx = true;
  if (seconds <= 0) seconds = 10;

  auto adapters = ListAdapters();
  const Adapter* chosen = nullptr;
  Caps chosenActive;
  for (auto& a : adapters) {
    if (want && a.ifIndex != want) continue;
    char ip[32];
    inet_ntop(AF_INET, &a.addr, ip, sizeof(ip));
    printf("[%lu] %ls - %ls (%s, %s)\n", a.ifIndex, a.name, a.desc, ip, a.up ? "up" : "down");
    Caps sup = QueryCaps(g_supported, a.luid);
    Caps act = QueryCaps(g_active, a.luid);
    PrintCaps(g_fe ? "supported" : "hardware", sup);
    PrintCaps(g_fe ? "active" : "current", act);
    Cross x1 = CaptureCross(a.luid);
    if (x1.ok) {
      Sleep(100);
      Cross x2 = CaptureCross(a.luid);
      printf("    cross-ts  sys1 %llu hw %llu sys2 %llu (read window %.2f us)\n", x1.sys1, x1.hw, x1.sys2, QpcToUs((LONGLONG)(x1.sys2 - x1.sys1)));
      if (x2.ok && sup.hwHz) {
        double dSys = QpcToUs((LONGLONG)(x2.sys1 - x1.sys1));
        double dHw = (double)(LONGLONG)(x2.hw - x1.hw) * 1e6 / (double)sup.hwHz;
        printf("              over %.0f us: NIC clock advanced %.0f us (%.1f ppm vs QPC)\n", dSys, dHw, (dHw - dSys) / dSys * 1e6);
      }
    } else {
      printf("    cross-ts  error %lu\n", x1.err);
    }
    if (want) { chosen = &a; chosenActive = act; }
  }
  if (want && !chosen) { printf("No adapter with ifIndex %lu\n", want); return 1; }
  if (chosen) { printf("\n"); return SocketTest(*chosen, chosenActive, seconds, tx); }
  return 0;
}
