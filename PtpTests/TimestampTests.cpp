#include "..\PtpUtil\Timestamp.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PtpTests {

//A WSAMSG whose control data holds the given control messages, as WSARecvMsg returns it.
struct SControlMsg {
  char buf[0x100];
  ULONG used;
  WSAMSG msg;

  SControlMsg() : used(0) {
    ZeroMemory(buf, sizeof(buf));
    ZeroMemory(&msg, sizeof(msg));
    Sync();
  }
  void Add(int Level, int Type, const void* Data, size_t Size) {
    WSACMSGHDR* cm = (WSACMSGHDR*)(buf + used);
    cm->cmsg_len = WSA_CMSG_LEN(Size);
    cm->cmsg_level = Level;
    cm->cmsg_type = Type;
    CopyMemory(WSA_CMSG_DATA(cm), Data, Size);
    used += (ULONG)WSA_CMSG_SPACE(Size);
    Sync();
  }
  void Sync() {
    msg.Control.buf = buf;
    msg.Control.len = used;
  }
};

TEST_CLASS(TimestampTests) {
public:
  TEST_METHOD(RxTimestampNoControlData) {
    SControlMsg m;
    Assert::AreEqual((uint64_t)0, WinsockTs::RxTimestamp(m.msg));
  }

  TEST_METHOD(RxTimestampFound) {
    SControlMsg m;
    uint64_t ts = 0x0123456789ABCDEFULL;
    m.Add(SOL_SOCKET, WinsockTs::SO_TIMESTAMP_, &ts, sizeof(ts));
    Assert::AreEqual(ts, WinsockTs::RxTimestamp(m.msg));
  }

  TEST_METHOD(RxTimestampAfterOtherControlMessage) {
    SControlMsg m;
    IN_PKTINFO info;
    ZeroMemory(&info, sizeof(info));
    m.Add(IPPROTO_IP, IP_PKTINFO, &info, sizeof(info));
    uint64_t ts = 42;
    m.Add(SOL_SOCKET, WinsockTs::SO_TIMESTAMP_, &ts, sizeof(ts));
    Assert::AreEqual(ts, WinsockTs::RxTimestamp(m.msg));
  }

  TEST_METHOD(RxTimestampIgnoresOtherLevel) {
    SControlMsg m;
    uint64_t ts = 42;
    m.Add(IPPROTO_IP, WinsockTs::SO_TIMESTAMP_, &ts, sizeof(ts));
    Assert::AreEqual((uint64_t)0, WinsockTs::RxTimestamp(m.msg));
  }

  TEST_METHOD(SoftwareSourceReturnsWakeTime) {
    SControlMsg m;
    uint64_t ts = 42;
    m.Add(SOL_SOCKET, WinsockTs::SO_TIMESTAMP_, &ts, sizeof(ts));
    CSoftwareTimestamps source;
    STimePair wake = { 133000000000000000ULL, 123456789 };
    uint64_t t = 0;
    Assert::IsTrue(source.RxTime(wake, m.msg, t));
    Assert::AreEqual(wake.SystemTime, t);
  }

  TEST_METHOD(SoftwareSourceSendsTimeBeforeSend) {
    CSoftwareTimestamps source;
    char buf[0x40];
    Assert::AreEqual((ULONG)0, source.TxControl(7, buf, sizeof(buf)));
    STimePair before = { 133000000000000000ULL, 123456789 };
    uint64_t t = 0;
    Assert::IsTrue(ETxResult::Ready == source.TxTime(7, before, t));
    Assert::AreEqual(before.SystemTime, t);
  }

  TEST_METHOD(HardwareTxControlCarriesId) {
    CHardwareTimestamps source;
    SControlMsg m;
    m.used = source.TxControl(0x12345678, m.buf, sizeof(m.buf));
    m.Sync();
    Assert::AreEqual((ULONG)WSA_CMSG_SPACE(sizeof(uint32_t)), m.used);
    WSACMSGHDR* cm = WSA_CMSG_FIRSTHDR(&m.msg);
    Assert::IsNotNull(cm);
    Assert::AreEqual((int)SOL_SOCKET, (int)cm->cmsg_level);
    Assert::AreEqual(WinsockTs::SO_TIMESTAMP_ID_, (int)cm->cmsg_type);
    uint32_t id = 0;
    CopyMemory(&id, WSA_CMSG_DATA(cm), sizeof(id));
    Assert::AreEqual((uint32_t)0x12345678, id);
  }

  TEST_METHOD(HardwareSourceNotReadyBeforeOpen) {
    CHardwareTimestamps source;
    Assert::IsFalse(source.Ready());
    SControlMsg m;
    uint64_t ts = 42;
    m.Add(SOL_SOCKET, WinsockTs::SO_TIMESTAMP_, &ts, sizeof(ts));
    STimePair wake = { 133000000000000000ULL, 123456789 };
    uint64_t t = 0;
    Assert::IsFalse(source.RxTime(wake, m.msg, t));
  }
};

/*
CNicClock against a simulated NIC: QPC at 10 MHz. By default the NIC is like the ConnectX-5
tested: nominally 156.25 MHz, actually running RATE_PPM fast. INTEL_HZ is the I219-LM tested,
which reports 125 MHz but counts at 1.008 GHz. A cross-timestamp is taken every second with a 1 us
read window.
*/
TEST_CLASS(NicClockTests) {
  static const int64_t QPF = 10000000;
  static const uint64_t NOMINAL_HZ = 156250000;
  static constexpr double RATE_PPM = 66.7;
  static constexpr double INTEL_HZ = 1008000000.0;
  static const uint64_t HW0 = 0x0000123400000000ULL;
  static const uint64_t QPC0 = 5000000000ULL;

  double hz;

  uint64_t HwAt(double Qpc) const {
    return HW0 + (uint64_t)(int64_t)((Qpc - QPC0) * hz / QPF);
  }

  SCrossTimestamp Cross(int Second, uint64_t WindowTicks = 10) const {
    uint64_t q1 = QPC0 + (uint64_t)Second * QPF;
    uint64_t q2 = q1 + WindowTicks;
    SCrossTimestamp x = { q1, HwAt((q1 + q2) / 2.0), q2 };
    return x;
  }

  CNicClock clock;

public:
  TEST_METHOD_INITIALIZE(Init) {
    hz = NOMINAL_HZ * (1.0 + RATE_PPM * 1e-6);
    clock.Reset(QPF);
  }

  TEST_METHOD(NotReadyUntilRateMeasured) {
    for (int s = 0; s < CNicClock::MIN_SPAN_S; ++s) {
      Assert::IsTrue(CNicClock::EAdd::Added == clock.Add(Cross(s)));
      Assert::IsFalse(clock.Ready());
      Assert::AreEqual(0.0, clock.MeasuredHz());
    }
    clock.Add(Cross(CNicClock::MIN_SPAN_S));
    Assert::IsTrue(clock.Ready());
  }

  TEST_METHOD(MeasuresRate) {
    for (int s = 0; s <= 10; ++s)
      clock.Add(Cross(s));
    Assert::AreEqual(hz, clock.MeasuredHz(), hz * 0.01e-6);
  }

  TEST_METHOD(MapsTimestampBetweenCrossTimestamps) {
    for (int s = 0; s <= 10; ++s)
      clock.Add(Cross(s));
    //0.7 s after the last cross-timestamp: within 10 ns
    double qpc = QPC0 + 10.7 * QPF;
    Assert::AreEqual(qpc, clock.ToQpc(HwAt(qpc)), 0.1);
  }

  TEST_METHOD(KeepsWorkingPastHistory) {
    for (int s = 0; s <= 3 * CNicClock::HISTORY; ++s)
      clock.Add(Cross(s));
    Assert::IsTrue(clock.Ready());
    double qpc = QPC0 + (3 * CNicClock::HISTORY + 0.5) * QPF;
    Assert::AreEqual(qpc, clock.ToQpc(HwAt(qpc)), 0.1);
  }

  TEST_METHOD(RejectsSlowRead) {
    clock.Add(Cross(0));
    //10 us window at 10 MHz = 100 ticks, above MAX_WINDOW_NS
    Assert::IsTrue(CNicClock::EAdd::Rejected == clock.Add(Cross(1, 100)));
  }

  TEST_METHOD(RestartsOnStep) {
    for (int s = 0; s <= 10; ++s)
      clock.Add(Cross(s));
    SCrossTimestamp x = Cross(11);
    x.Hw += (uint64_t)(hz / 1000);   //1 ms step
    Assert::IsTrue(CNicClock::EAdd::Restarted == clock.Add(x));
    Assert::IsFalse(clock.Ready());
  }

  TEST_METHOD(RestartsOnStepBeforeReady) {
    for (int s = 0; s < CNicClock::MIN_SPAN_S - 1; ++s)
      clock.Add(Cross(s));
    SCrossTimestamp x = Cross(CNicClock::MIN_SPAN_S - 1);
    x.Hw += (uint64_t)(hz / 500);    //2 ms step: more than MAX_RATE_PPM against the readings so far
    Assert::IsTrue(CNicClock::EAdd::Restarted == clock.Add(x));
    Assert::IsFalse(clock.Ready());
  }

  TEST_METHOD(RestartsOnSmallStepOnceReady) {
    for (int s = 0; s <= 10; ++s)
      clock.Add(Cross(s));
    SCrossTimestamp x = Cross(11);
    x.Hw += (uint64_t)(hz / 5000);   //200 us: within MAX_RATE_PPM over 1 s, but not the measured rate
    Assert::IsTrue(CNicClock::EAdd::Restarted == clock.Add(x));
  }

  TEST_METHOD(ToleratesReadJitter) {
    //alternate 0.1 us and 1 us windows: no restart, rate within 0.1 ppm
    for (int s = 0; s <= 20; ++s)
      Assert::IsTrue(CNicClock::EAdd::Added == clock.Add(Cross(s, (s % 2) ? 10 : 1)));
    Assert::AreEqual(hz, clock.MeasuredHz(), hz * 0.1e-6);
  }

  TEST_METHOD(UsesMeasuredRateNotReported) {
    //the Intel case: 8 times the reported frequency is measured and used
    hz = INTEL_HZ;
    for (int s = 0; s <= 10; ++s)
      Assert::IsTrue(CNicClock::EAdd::Added == clock.Add(Cross(s)));
    Assert::IsTrue(clock.Ready());
    Assert::AreEqual(INTEL_HZ, clock.MeasuredHz(), INTEL_HZ * 0.01e-6);
    double qpc = QPC0 + 10.7 * QPF;
    Assert::AreEqual(qpc, clock.ToQpc(HwAt(qpc)), 0.1);
  }

  TEST_METHOD(StoppedClockNeverReady) {
    //seen with an I219-LM on Windows 10 and an I350 on Windows Server 2022: the NIC clock reads 0
    for (int s = 0; s <= 30; ++s) {
      SCrossTimestamp x = Cross(s);
      x.Hw = 0;
      clock.Add(x);
      Assert::IsFalse(clock.Ready());
    }
  }

  TEST_METHOD(BackwardsClockNeverReady) {
    hz = -(double)NOMINAL_HZ;
    for (int s = 0; s <= 30; ++s) {
      clock.Add(Cross(s));
      Assert::IsFalse(clock.Ready());
    }
  }

  TEST_METHOD(SlowClockNeverReady) {
    hz = CNicClock::MIN_HZ / 2.0;
    for (int s = 0; s <= 30; ++s)
      clock.Add(Cross(s));
    Assert::IsFalse(clock.Ready());
  }
};

/*
CHardwareRecheck: Syncs at 8 a second, QPC at 10 MHz, a NIC clock at 1.008 GHz (the I219-LM).
*/
TEST_CLASS(HardwareRecheckTests) {
  static const int64_t QPF = 10000000;
  static constexpr double NIC_HZ = 1008000000.0;
  static const ULONGLONG T0 = 1000000;
  static const uint64_t TS0 = 5000000000000ULL;
  static const int64_t QPC0 = 20000000000LL;

  CHardwareRecheck recheck;
  int sync;   //Syncs fed so far

  //the next Count Syncs, 125 ms apart; Ts false: without a socket timestamp
  void Feed(int Count, bool Ts = true, double Hz = NIC_HZ) {
    for (int i = 0; i < Count; ++i, ++sync) {
      double t = sync * 0.125;
      recheck.OnSync(Ts ? TS0 + (uint64_t)(t * Hz) : 0, QPC0 + (int64_t)(t * QPF));
    }
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    recheck.Reset();
    sync = 0;
  }

  TEST_METHOD(NotWatchingBeforeFallback) {
    Feed(100);
    Assert::IsFalse(recheck.Watching());
    Assert::IsFalse(recheck.Due(T0 + 24 * 3600 * 1000ULL));
  }

  TEST_METHOD(NotWatchingWithoutMeasuredRate) {
    recheck.OnFallback(0.0, QPF, T0);
    Feed(100);
    Assert::IsFalse(recheck.Watching());
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(NotDueWhileTimestampsMissing) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(100, false);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(DueOnceTimestampsBackAndIntervalPassed) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(CHardwareRecheck::MIN_RUN);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS - 1));
    Assert::IsTrue(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(NeedsAFullRun) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(CHardwareRecheck::MIN_RUN - 1);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
    Feed(1);
    Assert::IsTrue(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(MissingTimestampBreaksTheRun) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(20);
    Feed(1, false);
    Feed(CHardwareRecheck::MIN_RUN - 1);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(IgnoresTimestampsInOtherUnits) {
    //QPC-like values (10 MHz) are not NIC clock ticks
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(100, true, (double)QPF);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(ToleratesWakeJitterOnly) {
    //5 % off the measured rate passes, 20 % doesn't
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(20, true, NIC_HZ * 1.05);
    Assert::IsTrue(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(20, true, NIC_HZ * 1.2);
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(StopsWatchingAfterReturn) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Feed(20);
    recheck.OnReturn();
    Assert::IsFalse(recheck.Watching());
    Assert::IsFalse(recheck.Due(T0 + CHardwareRecheck::RECHECK_MS));
  }

  TEST_METHOD(BacksOffWhenReturnDoesNotHold) {
    ULONGLONG t = T0;
    ULONGLONG expected = CHardwareRecheck::RECHECK_MS;
    for (int i = 0; i < 10; ++i) {
      recheck.OnFallback(NIC_HZ, QPF, t);
      Assert::AreEqual(expected, recheck.Interval());
      Feed(20);
      Assert::IsFalse(recheck.Due(t + expected - 1));
      Assert::IsTrue(recheck.Due(t + expected));
      recheck.OnReturn();
      t += expected;
      expected = (expected * 2 < CHardwareRecheck::MAX_RECHECK_MS) ? expected * 2 : CHardwareRecheck::MAX_RECHECK_MS;
    }
    Assert::AreEqual(CHardwareRecheck::MAX_RECHECK_MS, recheck.Interval());
  }

  TEST_METHOD(NoBackoffWithoutReturn) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    recheck.OnFallback(NIC_HZ, QPF, T0 + 1000);
    Assert::AreEqual(CHardwareRecheck::RECHECK_MS, recheck.Interval());
  }

  TEST_METHOD(ResetStartsTheIntervalAgain) {
    recheck.OnFallback(NIC_HZ, QPF, T0);
    recheck.OnReturn();
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Assert::AreEqual(2 * CHardwareRecheck::RECHECK_MS, recheck.Interval());
    recheck.Reset();
    Assert::IsFalse(recheck.Watching());
    recheck.OnFallback(NIC_HZ, QPF, T0);
    Assert::AreEqual(CHardwareRecheck::RECHECK_MS, recheck.Interval());
  }
};

}
