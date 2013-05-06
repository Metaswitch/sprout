/**
 * @file sasevent.h
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

#pragma once

namespace SASEvent {

const int HTTP_REQ = 0;
const int HTTP_RSP = 1;
const int HTTP_ERR = 2;

const int RX_SIP_MSG = 0x50100010;
const int TX_SIP_MSG = 0x50100011;
const int TX_HSS_BASE = 0x50100100;
const int TX_HSS_REQ = TX_HSS_BASE + HTTP_REQ;
const int RX_HSS_RSP = TX_HSS_BASE + HTTP_RSP;
const int RX_HSS_ERR = TX_HSS_BASE + HTTP_ERR;
const int TX_XDM_GET_BASE = 0x50100200;
const int TX_XDM_GET_REQ = TX_XDM_GET_BASE + HTTP_REQ;
const int RX_XDM_GET_RSP = TX_XDM_GET_BASE + HTTP_RSP;
const int RX_XDM_GET_ERR = TX_XDM_GET_BASE + HTTP_ERR;
const int TX_XDM_PUT_BASE = 0x50100210;
const int TX_XDM_PUT_REQ = TX_XDM_PUT_BASE + HTTP_REQ;
const int RX_XDM_PUT_RSP = TX_XDM_PUT_BASE + HTTP_RSP;
const int RX_XDM_PUT_ERR = TX_XDM_PUT_BASE + HTTP_ERR;
const int TX_XDM_DEL_BASE = 0x50100220;
const int TX_XDM_DEL_REQ = TX_XDM_DEL_BASE + HTTP_REQ;
const int RX_XDM_DEL_RSP = TX_XDM_DEL_BASE + HTTP_RSP;
const int RX_XDM_DEL_ERR = TX_XDM_DEL_BASE + HTTP_ERR;
const int ENUM_START = 0x50100300;
const int ENUM_MATCH = 0x50100301;
const int ENUM_INCOMPLETE = 0x50100302;
const int ENUM_COMPLETE = 0x50100303;
const int TX_ENUM_REQ = 0x50100310;
const int RX_ENUM_RSP = 0x50100311;
const int RX_ENUM_ERR = 0x50100312;

} // namespace SASEvent

namespace SASMarker {

const int INIT_TIME = 0x01000003;
const int END_TIME = 0x01000004;
const int CALLING_DN = 0x01000006;
const int CALLED_DN = 0x01000007;
const int SIP_CALL_ID = 0x010C0001;

} // namespace SASMarker
