/**
 * @file mockscscfsproutlettsx.h  Mock Application Server interfaces.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCKSCSCFSPROUTLETTSX_H__
#define MOCKSCSCFSPROUTLETTSX_H__

#include "gmock/gmock.h"
#include "scscfsproutlet.h"

class MockSCSCFSproutletTsx : public SCSCFSproutletTsx
{
public:
  MockSCSCFSproutletTsx(SCSCFSproutlet* scscf, pjsip_method_e req_type) :
    SCSCFSproutletTsx(scscf, req_type)
  {}

  MOCK_METHOD1(get_pool, pj_pool_t*(const pjsip_msg*));
};

#endif
