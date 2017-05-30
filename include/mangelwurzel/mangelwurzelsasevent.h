/**
 * @file mangelwurzelsasevent.h Mangelwurzel-specific SAS event IDs
 *
 * Copyright (C) Metaswitch Networks 2014
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MANGELWURZELSASEVENT_H__
#define MANGELWURZELSASEVENT_H__

#include "sasevent.h"

namespace SASEvent
{
  //----------------------------------------------------------------------------
  // Mangelwurzel events.
  //----------------------------------------------------------------------------
  const int INVALID_MANGALGORITHM = MANGELWURZEL_BASE + 0x000000;
  const int MANGELWURZEL_INITIAL_REQ = MANGELWURZEL_BASE + 0x000001;
  const int MANGELWURZEL_IN_DIALOG_REQ = MANGELWURZEL_BASE + 0x000002;
} //namespace SASEvent

#endif
