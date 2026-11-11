#include "SyncRequest.h"
#include <strsafe.h>

static inline uint64_t SystemTimeNs(uint64_t St) {
  return SystemTimeToPtp(St) * 100UL;
}

bool SSyncRequest::Sync(const PtpMessage& Msg, uint64_t SyncRxSystemTime, int64_t* out_Offset) {
  TSRWExclusiveLock l(lock);
  sync_id = Msg.Header.sequenceId;
  sync_rx_t2 = SystemTimeNs(SyncRxSystemTime);
  sync_source = Msg.Header.sourcePortIdentity;
  if (Msg.Header.twoStepFlag) {
    sync_tx_t1 = 0;
    //ensure sync cannot be used until followup arrives. 
    //followup_id and sync_id must be equal before a DelayResponse will
    //use the sync.
    followup_id = ~sync_id; 
    return false;
  } else { //no follow up expected 
    sync_tx_t1 = Msg.Message.Sync.originTimestamp.Nanoseconds();
    followup_id = sync_id;
    if (out_Offset != nullptr)
       *out_Offset = sync_tx_t1 - sync_rx_t2;
  }
  return true;
}

bool SSyncRequest::SyncFollowUp(const PtpMessage& Msg, int64_t* out_Offset) {
  TSRWExclusiveLock l(lock);
  //sync_rx_t2 != 0: a Sync has been received (a fresh object has sync_id 0, so a Follow_Up
  //with sequence 0 would otherwise match before any Sync and give a nonsense offset)
  if ((Msg.Header.sequenceId == sync_id) && (sync_tx_t1 == 0) && (sync_rx_t2 != 0) && (Msg.Header.sourcePortIdentity == sync_source)) {
    sync_tx_t1 = Msg.Message.Follow_Up.originTimestamp.Nanoseconds();
    followup_id = sync_id;
    if (out_Offset != nullptr)
       *out_Offset = sync_tx_t1 - sync_rx_t2;
    return true;
  }
  return false;
}

//The sequence id is taken before the send and t3 is given afterwards, so the system time can be read
//as close to the send as possible (software) or the NIC's transmit timestamp collected (hardware).
uint16_t SSyncRequest::GetDelayRequestSequenceId() {
  TSRWExclusiveLock l(lock);
  dr_tx_t3 = 0;
  dr_rx_t4 = 0;
  return _byteswap_ushort(++dr_seq_id);
}

bool SSyncRequest::DelayRequestTx(uint16_t SequenceId, uint64_t DrTxSystemTime, int64_t& out_Offset) {
  TSRWExclusiveLock l(lock);
  if (SequenceId != dr_seq_id)
    return false;   //a newer Delay_Req has been sent since
  dr_tx_t3 = SystemTimeNs(DrTxSystemTime);
  if (dr_rx_t4 == 0)
    return false;
  uint64_t t4 = dr_rx_t4;
  dr_rx_t4 = 0;
  return Complete(t4, out_Offset);
}

void SSyncRequest::Reset() {
  TSRWExclusiveLock l(lock);
  sync_id = 0;
  followup_id = 1;
  sync_rx_t2 = 0;
  sync_tx_t1 = 0;
  sync_source = { 0 };
  dr_tx_t3 = 0;
  dr_rx_t4 = 0;
}

void SSyncRequest::SetPortIdentity(const PortIdentity& Identity) {
  TSRWExclusiveLock l(lock);
  port_identity = Identity;
}

/*

offset required by w32time is gmc_time - system_time in ns100.

for definitions of t1, t2, t3, t4 see IEEE 1588:2008 
section 11.3.1 "Delay request-response mechanism"

mean delay 
((t4-t1)-(t3-t2))/2

offset is t1 + mean_delay - t2;

=> offset
t4/2 - t1/2 -t3/2 + t2/2  + t1 - t2

offset = t4/2 + t1/2 - t3/2 - t2/2 = (t4 + t1 - t3 - t2)/2;

*/

bool SSyncRequest::DelayRequestRx(const PtpMessage& Msg, int64_t& out_Offset) {
  TSRWExclusiveLock l(lock);
  //the packet is a response to a query by this provider, from the master whose Sync we hold
  if ((Msg.Header.sequenceId != dr_seq_id) || !(Msg.Message.Delay_Resp.requestingPortIdentity == port_identity) ||
    !(Msg.Header.sourcePortIdentity == sync_source))
    return false;
  uint64_t t4 = Msg.Message.Delay_Resp.receiveTimestamp.Nanoseconds();
  if (dr_tx_t3 == 0) {
    //the transmit timestamp has not been collected yet; DelayRequestTx completes the exchange
    dr_rx_t4 = t4;
    return false;
  }
  return Complete(t4, out_Offset);
}

bool SSyncRequest::Complete(uint64_t DrRxT4, int64_t& out_Offset) const {
  //delay requests are randomly timed and a response could arrive between a sync and a followup. This means that the
  //dr will be ignored but this is OK - it is very unlikely and there will be DR along in a second or so.
  if ((sync_id != followup_id) || (sync_tx_t1 == 0) || (sync_rx_t2 == 0) || (dr_tx_t3 == 0))
    return false;

  //avoid funky rollover malarky
  int64_t a(sync_tx_t1 - sync_rx_t2);
  int64_t b(DrRxT4 - dr_tx_t3);
  out_Offset = (a + b) / 2;

#ifdef _DEBUG
  wchar_t buf[0x60];
  StringCchPrintf(buf, 0x60, L"DR Response: %llu\t%llu\t%llu\t%llu\tOffset=%lld\n", sync_tx_t1 / 1000, sync_rx_t2 / 1000, dr_tx_t3 / 1000, DrRxT4 / 1000, out_Offset);
  OutputDebugString(buf);
#endif
  //is is useful or necessary to invalidate the sync? I don't think it is.
  //sync and DR are independent of each other. A sync can be used by more than one DR - all the DRs will have
  //some variation and go into the filter so they are not useless.
  return true;
}