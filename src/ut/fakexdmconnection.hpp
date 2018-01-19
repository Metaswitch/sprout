/**
 * @file fakexdmconnection.hpp Header file for fake XDM connection (for testing).
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#include <string>
#include <map>
#include "log.h"
//#include "fakehttpconnection.hpp"
#include "snmp_event_accumulator_table.h"
#include "xdmconnection.h"

/// XDMConnection that writes to/reads from a local map rather than the XDMS.
class FakeXDMConnection : public XDMConnection
{
public:
  FakeXDMConnection();
  ~FakeXDMConnection();

  void put(const std::string& uri, const std::string& doc);
  void flush_all();

private:
//  FakeHttpConnection* _fakehttp;  //< alias for _http, with more specific type.
};
