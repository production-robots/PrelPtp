#include "Ptp.h"

#include <stdlib.h>

struct SLeapSecond {
  uint64_t Utc;          //UTC time the new offset took effect, ns100 since 1970
  uint64_t LeapSeconds;  //TAI - UTC from then on, ns100
};

static constexpr uint64_t SYSTEM_TICKS = 10000000ull;
static constexpr uint64_t SYSTEM_TICKS_PER_MS = 10000ull;
static constexpr uint64_t SEC_PER_DAY = 3600 * 24;
static constexpr uint64_t PTP_EPOCH_SECONDS = 11644473600LL;
static constexpr uint64_t PTP_EPOCH_TICKS = PTP_EPOCH_SECONDS * SYSTEM_TICKS;

static constexpr uint64_t PTP_SEC(const int Year, const int Day) {
  return (Day + ((Year - 1970) * 365) + ((Year - 1968) / 4) +
    ((Year % 4) || (Day >= 60) ? 0 : -1)) * SEC_PER_DAY;
}

uint32_t _TEST_PTP_DAYS(int Y, int D) {
  return (uint32_t)(PTP_SEC(Y, D) / SEC_PER_DAY);
}

#define LS(Y, D, Offset) {PTP_SEC(Y,D)*SYSTEM_TICKS, Offset*SYSTEM_TICKS}

#define JAN 0
#define JUL 181  //assuming non leap year. PTP_SEC corrects for this.

static constexpr SLeapSecond LST[] = {
  LS(2017, JAN, 37),
  LS(2015, JUL, 36),
  LS(2012, JUL, 35),
  LS(2009, JAN, 34),
  LS(2006, JAN, 33),
  LS(1999, JAN, 32),
  LS(1997, JUL, 31),
  LS(1996, JAN, 30),
  LS(1994, JUL, 29),
  LS(1993, JUL, 28),
  LS(1992, JUL, 27),
  LS(1991, JAN, 26),
  LS(1990, JAN, 25),
  LS(1988, JAN, 24),
  LS(1985, JUL, 23),
  LS(1983, JUL, 22),
  LS(1982, JUL, 21),
  LS(1981, JUL, 20),
  LS(1980, JAN, 19),
  LS(1979, JAN, 18),
  LS(1978, JAN, 17),
  LS(1977, JAN, 16),
  LS(1976, JAN, 15),
  LS(1975, JAN, 14),
  LS(1974, JAN, 13),
  LS(1973, JAN, 12),
  LS(1972, JUL, 11)   //< this assume 10. Not really true before Jan 1972
};

//handle historical jumps in PTP. Offset will remain 37 forever and future leap seconds will be 
//inserted into the windows system timeline. See above.

//offset in force at a UTC time (ns100 since 1970)
static uint64_t LsFromUtc(uint64_t Utc) {
  for (const auto& i : LST) {
    if (Utc >= i.Utc)
      return i.LeapSeconds;
  }
  return 10 * SYSTEM_TICKS;
}

//offset in force at a PTP (TAI) time. The table is keyed on UTC, so compare
//against the TAI time at which each offset took effect.
static uint64_t LsFromPtp(ptp_timestamp Ptp) {
  for (const auto& i : LST) {
    if (Ptp >= i.Utc + i.LeapSeconds)
      return i.LeapSeconds;
  }
  return 10 * SYSTEM_TICKS;
}

ptp_timestamp SystemTimeToPtp(system_time SystemTime) {
  uint64_t utc = SystemTime - PTP_EPOCH_TICKS;
  return utc + LsFromUtc(utc);
}

system_time PtpToSystemTime(ptp_timestamp PtpTime) {
  return PtpTime - LsFromPtp(PtpTime) + PTP_EPOCH_TICKS;
}

uint32_t PtpMessage::Size() const {
  uint32_t len(sizeof(Header));
  switch (Header.messageType) {
    case EMessageType::Announce: len += sizeof(AnnounceMessage); break;
    case EMessageType::Sync: len += sizeof(SyncMessage); break;
    case EMessageType::Delay_Req: len += sizeof(Delay_ReqMessage); break;
    case EMessageType::Follow_Up: len += sizeof(Follow_UpMessage); break;
    case EMessageType::Delay_Resp: len += sizeof(Delay_RespMessage); break;
    case EMessageType::Pdelay_Resp: len += sizeof(Pdelay_RespMessage); break;
    case EMessageType::Pdelay_Resp_Follow_Up: len += sizeof(Pdelay_Resp_Follow_UpMessage); break;
  }
  return len;
}
