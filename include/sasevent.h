/**
 * @file sasevent.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#ifndef SASEVENT_H__
#define SASEVENT_H__

#include <string>

namespace SASEvent {

  const std::string CURRENT_RESOURCE_BUNDLE = "org.projectclearwater.sprout.20131107";

  const int SIP_BASE = 0x010000;
  const int HTTP_BASE = 0x020000;
  const int DNS_BASE = 0x030000;

  const int HTTP_REQ = 0;
  const int HTTP_RSP = 1;
  const int HTTP_ERR = 2;

  const int RX_SIP_MSG = SIP_BASE + 0;
  const int TX_SIP_MSG = SIP_BASE + 1;

  const int TX_HSS_BASE = HTTP_BASE + 0x00;
  const int TX_HSS_REQ = TX_HSS_BASE + HTTP_REQ;
  const int RX_HSS_RSP = TX_HSS_BASE + HTTP_RSP;
  const int RX_HSS_ERR = TX_HSS_BASE + HTTP_ERR;

  const int TX_XDM_BASE = HTTP_BASE + 0x40;
  const int TX_XDM_GET_BASE = TX_XDM_BASE;
  const int TX_XDM_GET_REQ = TX_XDM_GET_BASE + HTTP_REQ;
  const int RX_XDM_GET_RSP = TX_XDM_GET_BASE + HTTP_RSP;
  const int RX_XDM_GET_ERR = TX_XDM_GET_BASE + HTTP_ERR;

  const int ENUM_START = DNS_BASE + 0;
  const int ENUM_MATCH = DNS_BASE + 1;
  const int ENUM_INCOMPLETE = DNS_BASE + 2;
  const int ENUM_COMPLETE = DNS_BASE + 3;
  const int TX_ENUM_REQ = DNS_BASE + 4;
  const int RX_ENUM_RSP = DNS_BASE + 5;
  const int RX_ENUM_ERR = DNS_BASE + 6;

} // namespace SASEvent

#endif
