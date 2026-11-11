#include "..\PtpUtil\Filter.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PtpTests {

static ULONGLONG g_now;
static ULONGLONG WINAPI FakeTick() { return g_now; }

static const int64_t OUTLIER = 5000000; //5 ms, as used by the provider

TEST_CLASS(Filter) {
  CFilter f{ OUTLIER };

  void Fill(int Count, int64_t Value) {
    for (int i = 0; i < Count; ++i)
      Assert::IsTrue(f.AddSample(Value) == CFilter::EAddResult::Accepted);
  }

  int64_t Mean() {
    int64_t mean = 0;
    Assert::IsTrue(f.GetMean(mean));
    return mean;
  }

public:
  TEST_METHOD_INITIALIZE(Init) {
    g_now = 1000000;
    f.SetTickSource(FakeTick);
  }

  TEST_METHOD(EmptyFilterHasNoMean) {
    int64_t mean = 0;
    Assert::IsTrue(f.Empty());
    Assert::IsFalse(f.GetMean(mean));
  }

  TEST_METHOD(MeanOfPartlyFilledWindow) {
    f.AddSample(100);
    f.AddSample(200);
    f.AddSample(600);
    Assert::IsFalse(f.Empty());
    Assert::AreEqual(300LL, Mean());
  }

  TEST_METHOD(MeanSlidesOnceWindowIsFull) {
    f.SetLength(4);
    Fill(1, 100); Fill(1, 200); Fill(1, 300); Fill(1, 400);
    Assert::AreEqual(250LL, Mean());
    Fill(1, 500);  //100 drops out
    Assert::AreEqual(350LL, Mean());
    Fill(1, 600);  //200 drops out
    Assert::AreEqual(450LL, Mean());
  }

  TEST_METHOD(NegativeOffsets) {
    f.SetLength(2);
    Fill(1, -1000);
    Fill(1, -3000);
    Assert::AreEqual(-2000LL, Mean());
  }

  TEST_METHOD(LengthBelowOneIsClampedToOne) {
    f.SetLength(0);
    Fill(1, 100);
    Fill(1, 200);
    Assert::AreEqual(200LL, Mean());
  }

  TEST_METHOD(LengthAboveMaximumIsClampedToMaximum) {
    f.SetLength(1000);
    for (int i = 0; i <= CFilter::MAX_LENGTH; ++i)  //MAX_LENGTH + 1 samples: 0, 1000 ... 20000
      Fill(1, i * 1000);
    //the first sample (0) has dropped out: mean of 1000..20000
    Assert::AreEqual(10500LL, Mean());
  }

  TEST_METHOD(SetLengthResets) {
    Fill(3, 100);
    f.SetLength(5);
    Assert::IsTrue(f.Empty());
  }

  TEST_METHOD(ResetEmpties) {
    Fill(3, 100);
    f.Reset();
    Assert::IsTrue(f.Empty());
  }

  TEST_METHOD(NoOutlierRejectionUntilWindowIsFull) {
    f.SetLength(4);
    Fill(3, 0);
    Assert::IsTrue(f.AddSample(10 * OUTLIER) == CFilter::EAddResult::Accepted);
  }

  TEST_METHOD(OutlierRejectedOnceWindowIsFull) {
    f.SetLength(4);
    Fill(4, 0);
    Assert::IsTrue(f.AddSample(OUTLIER + 1) == CFilter::EAddResult::Rejected);
    Assert::IsTrue(f.AddSample(-OUTLIER - 1) == CFilter::EAddResult::Rejected);
    Assert::AreEqual(0LL, Mean());
    Assert::AreEqual(2ULL, f.DroppedOutliers);
  }

  TEST_METHOD(SampleAtOutlierLimitIsAccepted) {
    f.SetLength(4);
    Fill(4, 0);
    Assert::IsTrue(f.AddSample(OUTLIER) == CFilter::EAddResult::Accepted);
    f.Reset();  //the accepted sample moved the mean
    Fill(4, 0);
    Assert::IsTrue(f.AddSample(-OUTLIER) == CFilter::EAddResult::Accepted);
  }

  TEST_METHOD(ReacquiresAfterConsecutiveOutliers) {
    f.SetLength(4);
    Fill(4, 0);
    const int64_t jumped = 20 * OUTLIER;
    for (int i = 1; i < CFilter::REACQUIRE_AFTER; ++i)
      Assert::IsTrue(f.AddSample(jumped) == CFilter::EAddResult::Rejected);
    Assert::IsTrue(f.AddSample(jumped) == CFilter::EAddResult::Reacquired);
    //restarted with only the new sample
    Assert::AreEqual(jumped, Mean());
  }

  TEST_METHOD(GoodSampleResetsOutlierCount) {
    f.SetLength(4);
    Fill(4, 0);
    for (int i = 1; i < CFilter::REACQUIRE_AFTER; ++i)
      Assert::IsTrue(f.AddSample(20 * OUTLIER) == CFilter::EAddResult::Rejected);
    Fill(1, 0);
    for (int i = 1; i < CFilter::REACQUIRE_AFTER; ++i)
      Assert::IsTrue(f.AddSample(20 * OUTLIER) == CFilter::EAddResult::Rejected);
    Assert::AreEqual(0LL, Mean());
  }

  TEST_METHOD(ReportsSampleAge) {
    Fill(1, 100);
    g_now += 3500;
    int64_t mean = 0;
    ULONGLONG age = 0;
    Assert::IsTrue(f.GetMean(mean, &age));
    Assert::AreEqual(3500ULL, age);
  }

  TEST_METHOD(AgeIsFromNewestSample) {
    Fill(1, 100);
    g_now += 3000;
    Fill(1, 100);
    g_now += 500;
    int64_t mean = 0;
    ULONGLONG age = 0;
    Assert::IsTrue(f.GetMean(mean, &age));
    Assert::AreEqual(500ULL, age);
  }

  TEST_METHOD(RestartsAfterGap) {
    f.SetMaxGap(10000);
    Fill(3, 100);
    g_now += 10001;
    Assert::IsTrue(f.AddSample(400) == CFilter::EAddResult::Restarted);
    Assert::AreEqual(400LL, Mean());
  }

  TEST_METHOD(GapEqualToLimitDoesNotRestart) {
    f.SetMaxGap(10000);
    Fill(1, 100);
    g_now += 10000;
    Assert::IsTrue(f.AddSample(300) == CFilter::EAddResult::Accepted);
    Assert::AreEqual(200LL, Mean());
  }

  TEST_METHOD(RestartAfterGapTakesPrecedenceOverOutlier) {
    //after a long gap the clock may have drifted a long way: the new sample must not be rejected
    f.SetLength(4);
    f.SetMaxGap(10000);
    Fill(4, 0);
    g_now += 60000;
    Assert::IsTrue(f.AddSample(20 * OUTLIER) == CFilter::EAddResult::Restarted);
    Assert::AreEqual(20 * OUTLIER, Mean());
  }

  TEST_METHOD(NoGapLimitByDefault) {
    Fill(1, 100);
    g_now += 24ULL * 3600 * 1000;
    Assert::IsTrue(f.AddSample(300) == CFilter::EAddResult::Accepted);
  }
};

}
