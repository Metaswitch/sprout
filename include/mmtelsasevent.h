/**
 * @file mmtelsasevent.h Memento-specific SAS event IDs
 *
 * project clearwater - ims in the cloud
 * copyright (c) 2014  metaswitch networks ltd
 *
 * this program is free software: you can redistribute it and/or modify it
 * under the terms of the gnu general public license as published by the
 * free software foundation, either version 3 of the license, or (at your
 * option) any later version, along with the "special exception" for use of
 * the program along with ssl, set forth below. this program is distributed
 * in the hope that it will be useful, but without any warranty;
 * without even the implied warranty of merchantability or fitness for
 * a particular purpose.  see the gnu general public license for more
 * details. you should have received a copy of the gnu general public
 * license along with this program.  if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * the author can be reached by email at clearwater@metaswitch.com or by
 * post at metaswitch networks ltd, 100 church st, enfield en2 6bq, uk
 *
 * special exception
 * metaswitch networks ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining openssl with the
 * software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the gpl. you must comply with the gpl in all
 * respects for all of the code used other than openssl.
 * "openssl" means openssl toolkit software distributed by the openssl
 * project and licensed under the openssl licenses, or a work based on such
 * software and licensed under the openssl licenses.
 * "openssl licenses" means the openssl license and original ssleay license
 * under which the openssl project distributes the openssl toolkit software,
 * as those licenses appear in the file license-openssl.
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
