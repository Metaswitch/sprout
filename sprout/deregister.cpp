/**
 * @file deregister.cpp Deregistration functions
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#include <string>
#include "regdata.h"

// LCOV_EXCL_START
void register_with_application_servers() {}
void deregister_with_application_servers() {}
void notify_application_servers() {}
// LCOV_EXCL_STOP

void expire_bindings(RegData::Store* store, const std::string aor, const std::string binding_id) {
      //We need the retry loop to handle the store's compare-and-swap.
      RegData::AoR* aor_data;
      do
      {
        aor_data = store->get_aor_data(aor);
        aor_data->remove_binding(binding_id);
      } while (!store->set_aor_data(aor, aor_data));

      delete aor_data;
};

// LCOV_EXCL_START
/* Factored out from code not covered by UTs.
   Could be covered in future by:
   * Putting a binding in a store
   * Calling this function
   * Checking the binding is gone
*/
void network_initiated_deregistration(RegData::Store* store, const std::string aor, const std::string binding_id) {
  expire_bindings(store, aor, binding_id);
  deregister_with_application_servers();
  notify_application_servers();
};
// LCOV_EXCL_STOP

void user_initiated_deregistration(RegData::Store* store, const std::string aor, const std::string binding_id) {
  expire_bindings(store, aor, binding_id);
};
