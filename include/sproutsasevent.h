/**
 * @file sproutsasevent.h Sprout-specific SAS event IDs
 *
 * project clearwater - ims in the cloud
 * copyright (c) 2013  metaswitch networks ltd
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

#ifndef SPROUTSASEVENT_H__
#define SPROUTSASEVENT_H__

#include "sasevent.h"

namespace SASEvent
{
  //----------------------------------------------------------------------------
  // Sprout events.
  //----------------------------------------------------------------------------
  const int ENUM_START = SPROUT_BASE + 0x000000;
  const int ENUM_MATCH = SPROUT_BASE + 0x000001;
  const int ENUM_INCOMPLETE = SPROUT_BASE + 0x000002;
  const int ENUM_COMPLETE = SPROUT_BASE + 0x000003;
  const int TX_ENUM_REQ = SPROUT_BASE + 0x000004;
  const int RX_ENUM_RSP = SPROUT_BASE + 0x000005;
  const int RX_ENUM_ERR = SPROUT_BASE + 0x000006;

  const int BGCF_FOUND_ROUTE = SPROUT_BASE + 0x000010;
  const int BGCF_DEFAULT_ROUTE = SPROUT_BASE + 0x000011;
  const int BGCF_NO_ROUTE = SPROUT_BASE + 0x000012;

  const int SCSCF_NONE_CONFIGURED = SPROUT_BASE + 0x000020;
  const int SCSCF_NONE_VALID = SPROUT_BASE + 0x000021;
  const int SCSCF_SELECTED = SPROUT_BASE + 0x000022;
  const int SCSCF_SELECTION_SUCCESS = SPROUT_BASE + 0x000023;
  const int SCSCF_RETRY = SPROUT_BASE + 0x000024;
  const int SCSCF_SELECTION_FAILED = SPROUT_BASE + 0x000025;
  const int SCSCF_ODI_INVALID = SPROUT_BASE + 0x000026;

  const int SIPRESOLVE_START = SPROUT_BASE + 0x000030;
  const int SIPRESOLVE_PORT_A_LOOKUP = SPROUT_BASE + 0x000031;
  const int SIPRESOLVE_NAPTR_LOOKUP = SPROUT_BASE + 0x000032;
  const int SIPRESOLVE_NAPTR_SUCCESS_SRV = SPROUT_BASE + 0x000033;
  const int SIPRESOLVE_NAPTR_SUCCESS_A = SPROUT_BASE + 0x000034;
  const int SIPRESOLVE_NAPTR_FAILURE = SPROUT_BASE + 0x000035;
  const int SIPRESOLVE_TRANSPORT_SRV_LOOKUP = SPROUT_BASE + 0x000036;
  const int SIPRESOLVE_SRV_LOOKUP = SPROUT_BASE + 0x000037;
  const int SIPRESOLVE_A_LOOKUP = SPROUT_BASE + 0x000038;
  const int SIPRESOLVE_IP_ADDRESS = SPROUT_BASE + 0x000039;

  const int AUTHENTICATION_NOT_NEEDED = SPROUT_BASE + 0x000040;
  const int AUTHENTICATION_FAILED = SPROUT_BASE + 0x000042;
  const int AUTHENTICATION_SUCCESS = SPROUT_BASE + 0x000043;
  const int AUTHENTICATION_CHALLENGE = SPROUT_BASE + 0x000044;

  const int SUBSCRIBE_START = SPROUT_BASE + 0x000050;
  const int SUBSCRIBE_FAILED = SPROUT_BASE + 0x000051;
  const int SUBSCRIBE_FAILED_EARLY = SPROUT_BASE + 0x000052;

  const int NOTIFICATION_FAILED = SPROUT_BASE + 0x000060;

  const int REGSTORE_GET_FOUND = SPROUT_BASE + 0x000070;
  const int REGSTORE_GET_NEW = SPROUT_BASE + 0x000071;
  const int REGSTORE_GET_FAILURE = SPROUT_BASE + 0x000072;
  const int REGSTORE_SET_START = SPROUT_BASE + 0x000073;
  const int REGSTORE_SET_SUCCESS = SPROUT_BASE + 0x000074;
  const int REGSTORE_SET_FAILURE = SPROUT_BASE + 0x000075;

  const int REGISTER_START = SPROUT_BASE + 0x000080;
  const int REGISTER_FAILED = SPROUT_BASE + 0x000081;
  const int REGISTER_AS_START = SPROUT_BASE + 0x000082;
  const int REGISTER_AS_FAILED = SPROUT_BASE + 0x000083;

  const int AVSTORE_SUCCESS = SPROUT_BASE + 0x000090;
  const int AVSTORE_FAILURE = SPROUT_BASE + 0x000091;

  const int HTTP_HOMESTEAD_DIGEST = SPROUT_BASE + 0x0000A0;
  const int HTTP_HOMESTEAD_VECTOR = SPROUT_BASE + 0x0000A1;
  const int HTTP_HOMESTEAD_UPDATE_REG = SPROUT_BASE + 0x0000A2;
  const int HTTP_HOMESTEAD_GET_REG = SPROUT_BASE + 0x0000A3;
  const int HTTP_HOMESTEAD_AUTH_STATUS = SPROUT_BASE + 0x0000A4;
  const int HTTP_HOMESTEAD_LOCATION = SPROUT_BASE + 0x0000A5;

  const int HTTP_HOMER_SIMSERVS = SPROUT_BASE + 0x0000B0;

  const int IFC_INVALID = SPROUT_BASE + 0x0000C0;
  const int IFC_NOT_MATCHED = SPROUT_BASE + 0x0000C1;
  const int IFC_TEST_MATCHED = SPROUT_BASE + 0x0000C2;
  const int IFC_MATCHED = SPROUT_BASE + 0x0000C3;

  const int TRANSPORT_FAILURE = SPROUT_BASE + 0x0000D0;

} //namespace SASEvent

#endif

