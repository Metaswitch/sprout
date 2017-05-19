/**
 * @file fakexdmconnection.cpp Fake XDM Connection (for testing).
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///----------------------------------------------------------------------------

#include <cstdio>

#include "utils.h"
#include "fakexdmconnection.hpp"

#include "fakesnmp.hpp"

using namespace std;

FakeXDMConnection::FakeXDMConnection() :
  XDMConnection(new FakeHttpConnection(), &SNMP::FAKE_EVENT_ACCUMULATOR_TABLE),
  _fakehttp((FakeHttpConnection*)_http)
{
}

FakeXDMConnection::~FakeXDMConnection()
{
}

void FakeXDMConnection::put(const std::string& uri, const std::string& doc)
{
  _fakehttp->put("/org.etsi.ngn.simservs/users/" + Utils::url_escape(uri) + "/simservs.xml", doc, "", 0);
}

void FakeXDMConnection::flush_all()
{
  _fakehttp->flush_all();
}
