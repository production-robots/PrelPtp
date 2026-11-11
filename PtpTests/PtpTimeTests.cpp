#include "..\PtpUtil\Ptp.h"
#include "..\PtpUtil\Util.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

//test hook in Ptp.cpp: days from 1970-01-01 to day D of year Y, where D is counted as if the year
//were not a leap year. The leap-second table only uses day 0 (1 January) and day 181 (1 July).
uint32_t _TEST_PTP_DAYS(int Y, int D);

namespace PtpTests {

static const uint64_t TICKS = 10000000ULL;              //ns100 per second
static const uint64_t EPOCH_1601_TO_1970 = 11644473600ULL;

//Windows system time (ns100 since 1601) for a Unix time in UTC
static uint64_t SystemTime(uint64_t UnixSeconds) {
  return (UnixSeconds + EPOCH_1601_TO_1970) * TICKS;
}

//PTP time (ns100 since 1970, TAI) for a Unix time in UTC and the TAI-UTC offset then in force
static uint64_t PtpTime(uint64_t UnixSeconds, uint64_t LeapSeconds) {
  return (UnixSeconds + LeapSeconds) * TICKS;
}

static const uint64_t Y2023 = 1700000000ULL;   //2023-11-14 22:13:20 UTC
static const uint64_t Y2017 = 1483228800ULL;   //2017-01-01 00:00:00 UTC: TAI-UTC became 37
static const uint64_t Y2016 = 1451606400ULL;   //2016-01-01 00:00:00 UTC: TAI-UTC was 36
static const uint64_t Y1972 = 63072000ULL;     //1972-01-01 00:00:00 UTC

TEST_CLASS(PtpTimeConversion) {
public:
  TEST_METHOD(DayCalculationHandlesLeapYears) {
    Assert::AreEqual(0u, _TEST_PTP_DAYS(1970, 0));
    Assert::AreEqual((uint32_t)(Y2017 / 86400), _TEST_PTP_DAYS(2017, 0));
    Assert::AreEqual(16617u, _TEST_PTP_DAYS(2015, 181));  //2015-07-01
    Assert::AreEqual(15522u, _TEST_PTP_DAYS(2012, 181));  //2012-07-01, a leap year
    Assert::AreEqual(15340u, _TEST_PTP_DAYS(2012, 0));    //2012-01-01, a leap year
    Assert::AreEqual(16983u, _TEST_PTP_DAYS(2016, 181));  //2016-07-01, a leap year
    Assert::AreEqual(1277u, _TEST_PTP_DAYS(1973, 181));   //1973-07-01
  }

  TEST_METHOD(SystemToPtpAddsCurrentLeapSeconds) {
    Assert::AreEqual(PtpTime(Y2023, 37), SystemTimeToPtp(SystemTime(Y2023)));
  }

  TEST_METHOD(SystemToPtpUsesHistoricalLeapSeconds) {
    Assert::AreEqual(PtpTime(Y2016, 36), SystemTimeToPtp(SystemTime(Y2016)));
    Assert::AreEqual(PtpTime(Y1972, 10), SystemTimeToPtp(SystemTime(Y1972)));
  }

  TEST_METHOD(PtpToSystemRemovesLeapSeconds) {
    Assert::AreEqual(SystemTime(Y2023), PtpToSystemTime(PtpTime(Y2023, 37)));
    Assert::AreEqual(SystemTime(Y2016), PtpToSystemTime(PtpTime(Y2016, 36)));
  }

  TEST_METHOD(SystemToPtpAroundLeapSecond) {
    Assert::AreEqual(PtpTime(Y2017 - 1, 36), SystemTimeToPtp(SystemTime(Y2017 - 1)));
    Assert::AreEqual(PtpTime(Y2017, 37), SystemTimeToPtp(SystemTime(Y2017)));
  }

  TEST_METHOD(PtpToSystemAroundLeapSecond) {
    //the 37 seconds before the change were converted with the new offset before this was fixed
    Assert::AreEqual(SystemTime(Y2017 - 30), PtpToSystemTime(PtpTime(Y2017 - 30, 36)));
    Assert::AreEqual(SystemTime(Y2017 - 1), PtpToSystemTime(PtpTime(Y2017 - 1, 36)));
    Assert::AreEqual(SystemTime(Y2017), PtpToSystemTime(PtpTime(Y2017, 37)));
  }

  TEST_METHOD(RoundTrip) {
    for (uint64_t t : { Y1972, Y2016, Y2017 - 1, Y2017, Y2023 }) {
      uint64_t sys = SystemTime(t) + 1234567;  //not on a whole second
      Assert::AreEqual(sys, PtpToSystemTime(SystemTimeToPtp(sys)));
    }
  }
};

}
