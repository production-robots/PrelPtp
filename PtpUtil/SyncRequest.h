#pragma once

#include "Util.h"

#include "Ptp.h"

/*
we ignore corrections which is bad: Get back to this &&&. 
see IEEE:1588 2008 section 11.6.2.

To understand the sync / delay mechanism including 
definitions of t1, t2, t3, t4 see IEEE 1588:2008
section 11.3.1 "Delay request-response mechanism"


(DR = Delay Request/Response cycle)

The interval between sync and delay request is arbitrary
and is cancelled out in the offset calculation. 
Delay requests are issued by the client at an arbitrary
cadence and syncs are issued by the gmc at an arbitrary 
cadence. When a DR is completed it references the most 
recent sync to calculate the current offset. 

*/

struct SSyncRequest {
  TSRWLock lock;

  //valid sync if (sync_id == followup_id)
  uint16_t sync_id;
  uint16_t followup_id; 
  uint64_t sync_rx_t2;  //t2  local  ns
  uint64_t sync_tx_t1;  //t1  master ns
  //the master port that sent the Sync. Follow_Up and Delay_Resp must come from the same port,
  //so messages from two masters are never combined.
  PortIdentity sync_source;


  uint64_t dr_tx_t3;    //t3  local ns, 0 until known
  uint16_t dr_seq_id;
  //t4 from a Delay_Resp that arrived before t3 was known (hardware transmit timestamps arrive
  //after the send, and the response can beat them). 0 if none.
  uint64_t dr_rx_t4;

  PortIdentity port_identity;

  //on receipt of sync
  bool Sync(const PtpMessage& Msg, uint64_t SyncRxSystemTime, int64_t* out_Offset);

  //on follow up
  bool SyncFollowUp(const PtpMessage& Msg, int64_t* out_Offset);

  //Starts a new Delay_Req: returns its sequence id in wire order, and forgets t3 and t4 of the last one.
  uint16_t GetDelayRequestSequenceId();

  //t3 of the Delay_Req with SequenceId (host order). Ignored if a newer Delay_Req has been started.
  //Returns true, with out_Offset in ns, if the Delay_Resp had already arrived and completes the exchange.
  bool DelayRequestTx(uint16_t SequenceId, uint64_t DrTxSystemTime, int64_t& out_Offset);

  //identity used to recognise responses to our delay requests (wire byte order)
  void SetPortIdentity(const PortIdentity& Identity);

  //on delay response. out_Offset is in ns. Returns false if t3 is not known yet: the response is
  //kept and DelayRequestTx completes the exchange.
  bool DelayRequestRx(const PtpMessage& Msg, int64_t& out_Offset);

  //forgets the current Sync and Delay_Req, for example when the master changes.
  //Keeps the Delay_Req sequence number and our port identity.
  void Reset();

  SSyncRequest() : sync_id(0), followup_id(1), sync_rx_t2(0), sync_tx_t1(0), sync_source({ 0 }), dr_tx_t3(0), dr_seq_id(Uniform()), dr_rx_t4(0), port_identity({ 0 }) {}

private:
  //offset from the current Sync and Delay_Req exchange, if the Sync is complete. Caller holds the lock.
  bool Complete(uint64_t DrRxT4, int64_t& out_Offset) const;
};

