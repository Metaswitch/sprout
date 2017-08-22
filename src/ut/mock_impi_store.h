/**
 * @file mock_impi_store.h
 *
 * Copyright (C) Metaswitch Networks 2016
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_IMPI_STORE_H__
#define MOCK_IMPI_STORE_H__

#include "impistore.h"

class MockImpiStore : public ImpiStore
{
public:
  MockImpiStore() : ImpiStore(NULL) {}
  virtual ~MockImpiStore() {}

  MOCK_METHOD2(set_impi, Store::Status(Impi* impi, SAS::TrailId trail));
  MOCK_METHOD2(get_impi, Impi*(const std::string& impi, SAS::TrailId trail));
  MOCK_METHOD3(get_impi_with_nonce, Impi*(const std::string& impi,
                                          const std::string& nonce,
                                          SAS::TrailId trail));
  MOCK_METHOD2(delete_impi, Store::Status(Impi* impi, SAS::TrailId trail));
};

#endif

