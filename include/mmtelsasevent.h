/**
 * @file mmtelsasevent.h Memento-specific SAS event IDs
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MMTELSASEVENT_H__
#define MMTELSASEVENT_H__

#include "sasevent.h"

namespace SASEvent
{
  //----------------------------------------------------------------------------
  // MMTEL events.
  //----------------------------------------------------------------------------
  const int RETRIEVING_SIMSERVS = MMTEL_BASE + 0x000000;
  const int FAILED_RETRIEVE_SIMSERVS = MMTEL_BASE + 0x000001;
  const int ORIGINATING_SERVICES_ENABLED = MMTEL_BASE + 0x000002;
  const int ORIGINATING_SERVICES_DISABLED = MMTEL_BASE + 0x000003;
  const int TERMINATING_SERVICES_ENABLED = MMTEL_BASE + 0x000004;
  const int TERMINATING_SERVICES_DISABLED = MMTEL_BASE + 0x000005;

  const int CALL_DIVERSION_INVOKED = MMTEL_BASE + 0x000010;
  const int NO_TARGET_PARAM = MMTEL_BASE + 0x000011;
  const int UNRECOGNIZED_CONDITION = MMTEL_BASE + 0x000012;
  const int UNPARSEABLE_NO_REPLY_TIMER = MMTEL_BASE + 0x000013;
  const int CALL_DIVERSION_ENABLED = MMTEL_BASE + 0x000014;

  const int DIVERTING_CALL = MMTEL_BASE + 0x000020;

} //namespace SASEvent

#endif
