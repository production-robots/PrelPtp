#include "..\PtpUtil\Validation.h"
#include "..\PtpUtil\Filter.h"
#include "..\PtpUtil\MessagePath.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PtpTests {

TEST_CLASS(DomainFilter) {
public:
  TEST_METHOD(AnyAcceptsEveryDomain) {
    Assert::IsTrue(DomainAccepted(PTP_DOMAIN_ANY, 0));
    Assert::IsTrue(DomainAccepted(PTP_DOMAIN_ANY, 127));
    Assert::IsTrue(DomainAccepted(PTP_DOMAIN_ANY, 255));
  }

  TEST_METHOD(ConfiguredDomainAcceptsOnlyItself) {
    Assert::IsTrue(DomainAccepted(0, 0));
    Assert::IsFalse(DomainAccepted(0, 1));
    Assert::IsTrue(DomainAccepted(24, 24));
    Assert::IsFalse(DomainAccepted(24, 0));
    Assert::IsTrue(DomainAccepted(255, 255));
    Assert::IsFalse(DomainAccepted(255, 254));
  }
};

//the domain field in the setup program
TEST_CLASS(DomainText) {
  static DWORD Parsed(const wchar_t* Text) {
    DWORD d = 12345;
    Assert::IsTrue(ParseDomain(Text, d), Text);
    return d;
  }
  static void Rejected(const wchar_t* Text) {
    DWORD d = 12345;
    Assert::IsFalse(ParseDomain(Text, d), Text);
    Assert::AreEqual(12345UL, d, L"output must be unchanged");
  }

public:
  TEST_METHOD(Numbers) {
    Assert::AreEqual(0UL, Parsed(L"0"));
    Assert::AreEqual(127UL, Parsed(L"127"));
    Assert::AreEqual(255UL, Parsed(L"255"));
    Assert::AreEqual(7UL, Parsed(L"007"));
    Assert::AreEqual(255UL, Parsed(L"0255"));
  }

  TEST_METHOD(LeadingSpacesIgnored) {
    Assert::AreEqual(127UL, Parsed(L"  127"));
  }

  TEST_METHOD(DescriptionAfterNumber) {
    //as offered in the drop-down
    Assert::AreEqual(0UL, Parsed(L"0 - default profile"));
    Assert::AreEqual(127UL, Parsed(L"127 - SMPTE ST 2059-2"));
    Assert::AreEqual(24UL, Parsed(L"24 - ITU-T G.8275.1"));
    Assert::AreEqual(44UL, Parsed(L"44 - ITU-T G.8275.2"));
    Assert::AreEqual(5UL, Parsed(L"5\tlab"));
    Assert::AreEqual(5UL, Parsed(L"5 "));
  }

  TEST_METHOD(Any) {
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L"Any"));
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L"any"));
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L"ANY"));
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L"  Any domain"));
  }

  TEST_METHOD(EmptyMeansAny) {
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L""));
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(L"   "));
  }

  TEST_METHOD(OutOfRangeRejected) {
    Rejected(L"256");
    Rejected(L"999");
    Rejected(L"1000");
    Rejected(L"99999999999999999999");
  }

  TEST_METHOD(NotANumberRejected) {
    Rejected(L"-1");
    Rejected(L"12a");
    Rejected(L"1.5");
    Rejected(L"127-SMPTE");
    Rejected(L"x");
    Rejected(L"domain 127");
    Rejected(nullptr);
  }

  TEST_METHOD(Format) {
    wchar_t buf[0x10];
    FormatDomain(127, buf, ARRAYSIZE(buf));
    Assert::AreEqual(L"127", buf);
    FormatDomain(0, buf, ARRAYSIZE(buf));
    Assert::AreEqual(L"0", buf);
    FormatDomain(PTP_DOMAIN_ANY, buf, ARRAYSIZE(buf));
    Assert::AreEqual(L"Any", buf);
  }

  TEST_METHOD(FormatThenParseRoundTrips) {
    wchar_t buf[0x10];
    for (DWORD d = 0; d <= 255; ++d) {
      FormatDomain(d, buf, ARRAYSIZE(buf));
      Assert::AreEqual(d, Parsed(buf));
    }
    FormatDomain(PTP_DOMAIN_ANY, buf, ARRAYSIZE(buf));
    Assert::AreEqual(PTP_DOMAIN_ANY, Parsed(buf));
  }
};

}
