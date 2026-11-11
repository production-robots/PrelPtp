#include "MessagePath.h"
#include <strsafe.h>

CMessagePath::CMessagePath(SSyncRequest& Sync, CBmca& Bmca) :
  _sync(Sync), _bmca(Bmca), _pinned_address(0), _domain(PTP_DOMAIN_ANY), _disable_delay_request(false) {
}

void CMessagePath::Configure(DWORD PinnedAddress, DWORD DomainNumber, bool DisableDelayRequest) {
  _pinned_address = PinnedAddress;
  _domain = DomainNumber;
  _disable_delay_request = DisableDelayRequest;
  _bmca.SetDomain(DomainNumber);
}

void CMessagePath::OnMasterChanged(SOutcome& out_Outcome) {
  out_Outcome.MasterChanged = true;
  //never combine a Sync from one master with a Follow_Up or Delay_Resp from another
  if (!Pinned())
    _sync.Reset();
}

bool CMessagePath::Tick() {
  if (!_bmca.OnTick())
    return false;
  if (!Pinned())
    _sync.Reset();
  return true;
}

CMessagePath::SOutcome CMessagePath::Handle(PtpMessage& Message, int Size, DWORD FromAddress, uint64_t RxSystemTime) {
  SOutcome out;
  ZeroMemory(&out, sizeof(out));
  out.Result = EResult::Ignored;

  if ((Size < (int)sizeof(CommonMsgHeader)) || (Size > (int)sizeof(PtpMessage)))
    return out;

  Message.Header._ByteSwap();
  out.Type = Message.Header.messageType;
  out.Domain = Message.Header.domainNumber;

  //Delay_Req: our own, looped back on the event port, or another slave's. Neither shows
  //that a master is reachable.
  if (Message.Header.messageType == EMessageType::Delay_Req)
    return out;

  if (Pinned() && (FromAddress != _pinned_address)) {
    out.Result = EResult::WrongSource;
    return out;
  }
  if (!DomainAccepted(_domain, Message.Header.domainNumber)) {
    out.Result = EResult::WrongDomain;
    return out;
  }

  out.Result = EResult::Accepted;
  int body_size = Size - (int)sizeof(CommonMsgHeader);

  //expire masters whose Announce messages have stopped, whatever this message is
  if (_bmca.OnTick())
    OnMasterChanged(out);

  switch (Message.Header.messageType) {
  case EMessageType::Announce:
    if (body_size >= (int)sizeof(AnnounceMessage)) {
      Message.Message.Announce._ByteSwap();
      bool changed = false;
      _bmca.OnAnnounce(Message.Header, Message.Message.Announce, FromAddress, &changed);
      if (changed)
        OnMasterChanged(out);
    }
    return out;

  case EMessageType::Sync:
  case EMessageType::Follow_Up:
  case EMessageType::Delay_Resp:
    if (!Pinned() && !_bmca.IsSelected(Message.Header.sourcePortIdentity, Message.Header.domainNumber)) {
      out.Result = EResult::NotSelected;
      return out;
    }
    break;

  default:
    return out;
  }

  switch (Message.Header.messageType) {
  case EMessageType::Sync:
    if (body_size >= (int)sizeof(SyncMessage)) {
      Message.Message.Sync._ByteSwap();
      //with delay requests disabled the offset comes from t1 - t2 alone. Sync returns false
      //if a Follow_Up is expected.
      if (_disable_delay_request)
        out.HaveOffset = _sync.Sync(Message, RxSystemTime, &out.Offset);
      else
        _sync.Sync(Message, RxSystemTime, nullptr);
#ifdef ODS_DEBUG
      wchar_t buf[0x20];
      StringCchPrintf(buf, ARRAYSIZE(buf), L"Sync %d\n", Message.Header.sequenceId);
      OutputDebugString(buf);
#endif
    }
    break;

  case EMessageType::Follow_Up:
    if (body_size >= (int)sizeof(Follow_UpMessage)) {
      Message.Message.Follow_Up._ByteSwap();
      if (_disable_delay_request)
        out.HaveOffset = _sync.SyncFollowUp(Message, &out.Offset);
      else
        _sync.SyncFollowUp(Message, nullptr);
#ifdef ODS_DEBUG
      wchar_t buf[0x20];
      StringCchPrintf(buf, ARRAYSIZE(buf), L"FollowUp %d\n", Message.Header.sequenceId);
      OutputDebugString(buf);
#endif
    }
    break;

  case EMessageType::Delay_Resp:
    //with delay requests disabled (upstream of a Matrox LE5) the responses are to the card's
    //own delay requests, so t3 is unknown: ignore them
    if ((body_size >= (int)sizeof(Delay_RespMessage)) && !_disable_delay_request) {
      Message.Message.Delay_Resp._ByteSwap();
      out.HaveOffset = _sync.DelayRequestRx(Message, out.Offset);
#ifdef ODS_DEBUG
      if (out.HaveOffset) {
        wchar_t buf[0x40];
        StringCchPrintf(buf, ARRAYSIZE(buf), L"Add offset %lld from DelayReq %d\n", out.Offset, Message.Header.sequenceId);
        OutputDebugString(buf);
      }
#endif
    }
    break;

  default:
    break;
  }

  return out;
}

CRxDiagnosis::CRxDiagnosis() : _tick(GetTickCount64) {
  Reset();
}

void CRxDiagnosis::SetTickSource(TTickSource Tick) {
  TSRWExclusiveLock l(_lock);
  _tick = Tick;
  _last_usable = _tick();
}

void CRxDiagnosis::Reset() {
  TSRWExclusiveLock l(_lock);
  _state = EState::Ok;
  _last_usable = _tick();
  ZeroMemory(_last_domain_seen, sizeof(_last_domain_seen));
  _last_wrong_source = 0;
  _wrong_source_address = 0;
}

void CRxDiagnosis::OnOutcome(const CMessagePath::SOutcome& Outcome, DWORD FromAddress) {
  TSRWExclusiveLock l(_lock);
  ULONGLONG now = _tick();
  switch (Outcome.Result) {
  case CMessagePath::EResult::Accepted:
  case CMessagePath::EResult::NotSelected:  //the right domain and source: the BMCA reports on masters
    _last_usable = now;
    break;
  case CMessagePath::EResult::WrongDomain:
    _last_domain_seen[Outcome.Domain] = now;
    break;
  case CMessagePath::EResult::WrongSource:
    _last_wrong_source = now;
    _wrong_source_address = FromAddress;
    break;
  default:
    break;
  }
}

CRxDiagnosis::EReport CRxDiagnosis::Check(SDetail& out_Detail) {
  TSRWExclusiveLock l(_lock);
  ULONGLONG now = _tick();
  ZeroMemory(&out_Detail, sizeof(out_Detail));

  if ((now - _last_usable) <= UNUSABLE_AFTER_MS) {
    if (_state == EState::Ok)
      return EReport::None;
    _state = EState::Ok;
    return EReport::Resumed;
  }

  bool other_domains = false;
  for (int d = 0; d < 256; ++d) {
    if ((_last_domain_seen[d] != 0) && ((now - _last_domain_seen[d]) <= UNUSABLE_AFTER_MS)) {
      out_Detail.Domains[d] = true;
      other_domains = true;
    }
  }
  if (other_domains) {
    if (_state == EState::WrongDomain)
      return EReport::None;
    _state = EState::WrongDomain;
    return EReport::WrongDomain;
  }

  if ((_last_wrong_source != 0) && ((now - _last_wrong_source) <= UNUSABLE_AFTER_MS)) {
    out_Detail.OtherAddress = _wrong_source_address;
    if (_state == EState::WrongSource)
      return EReport::None;
    _state = EState::WrongSource;
    return EReport::WrongSource;
  }

  //no traffic at all: the message loops report that. Keep the state, so Resumed is still
  //reported if usable messages come back.
  return EReport::None;
}