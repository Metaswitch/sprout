/**
 * @file sifcservice.h
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2017  Metaswitch Networks Ltd
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

#ifndef SIFCSERVICE_H__
#define SIFCSERVICE_H__

#include <map>
#include <string>
#include <boost/thread.hpp>
#include "rapidxml/rapidxml.hpp"
#include <functional>

#include "updater.h"
#include "sas.h"
#include "ifc.h"

class SIFCService
{
public:
  SIFCService(std::string configuration = "./sifc.xml");
  ~SIFCService();

  /// Updates the shared IFC sets
  void update_sets();

  /// Get the IFCs that belong to a set of IDs
  void get_ifcs_from_id(std::multimap<int32_t, Ifc>& ifc_map,
                        const std::set<int32_t>& id,
                        SAS::TrailId trail) const;

private:
  std::map<int32_t, std::vector<std::pair<int32_t, Ifc>>> _shared_ifc_sets;
  std::string _configuration;
  Updater<void, SIFCService>* _updater;
  rapidxml::xml_document<>* _root;

  // Mark as mutable to flag that this can be modified without affecting the
  // external behaviour of the class, allowing for locking in 'const' methods.
  mutable boost::shared_mutex _sets_rw_lock;
};

#endif
