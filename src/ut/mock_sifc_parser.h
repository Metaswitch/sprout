/**
 * @file mock_sifc_parser.h
 * Mocks out parsing shared iFC set id into list of iFCs.
 *
 * Copyright (C) Metaswitch Networks
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_SIFC_PARSER_H__
#define MOCK_SIFC_PARSER_H__

#include <vector>

#include "gmock/gmock.h"
#include "sifcservice.h"

class MockSIFCService : public SIFCService
{
public:
  MockSIFCService();
  virtual ~MockSIFCService();

  MOCK_CONST_METHOD4(get_ifcs_from_id, void(std::multimap<int32_t, Ifc>&,
                                            const std::set<int32_t>&,
                                            std::shared_ptr<xml_document<> > ifc_doc,
                                            SAS::TrailId));

};

#endif
