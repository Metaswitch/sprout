/**
 * @file websockets.h Definitions for WebSockets class.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef WEBSOCKETS_H__
#define WEBSOCKETS_H__

#include <websocketpp/websocketpp.hpp>

extern pjsip_module mod_ws_transport;
extern pj_status_t init_websockets(unsigned short port);
extern void  destroy_websockets();

#endif
