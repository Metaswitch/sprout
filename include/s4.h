/**
 * @file s4.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


#ifndef S4_H__
#define S4_H__

#include <string>
#include <list>
#include <map>
#include <stdio.h>
#include <stdlib.h>

#include "sas.h"
#include "analyticslogger.h"
#include "associated_uris.h"
#include "astaire_aor_store.h"

class S4
{
public:
  /// S4 constructor.
  ///
  /// @param aor_store          - Pointer to the underlying data store interface
  S4(std::string id,
     AoRStore* aor_store,
     std::vector<S4*> remote_s4s);

  /// Destructor.
  virtual ~S4();

  HTTPCode handle_get(std::string aor_id,
                      AoR** aor,
                      SAS::TrailId trail);
  HTTPCode handle_delete(std::string aor_id,
                         SAS::TrailId trail);
  HTTPCode handle_put(std::string aor_id,
                      AoR* aor,
                      SAS::TrailId id);
  HTTPCode handle_patch(std::string aor_id,
                        PatchObject* patch_object,
                        SAS::TrailId trail);

private:
  void replicate_delete_cross_site(std::string aor_id,
                                   SAS::TrailId trail);
  void replicate_patch_cross_site(std::string aor_id,
                                  PatchObject* po,
                                  SAS::TrailId trail);
  void replicate_put_cross_site(std::string aor_id,
                                AoR* aor,
                                SAS::TrailId trail);

  std::string _id;
  AoRStore* _aor_store;
  std::vector<S4*> _remote_s4s;
};

#endif
