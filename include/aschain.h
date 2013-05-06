/**
 * @file aschain.h The AS chain data type.
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

///
///

#pragma once

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include <string>
#include <vector>

#include "callservices.h"
#include "sessioncase.h"


/// Short-lived data structure holding the details of a calculated target.
struct target
{
  pj_bool_t from_store;
  std::string aor;
  std::string binding_id;
  pjsip_uri* uri;
  std::list<pjsip_uri*> paths;
  pjsip_transport* transport;
};
typedef std::list<target> target_list;

/// The AS chain.
class AsChain
{
public:
  AsChain(const SessionCase& session_case,
          std::string served_user,
          std::vector<std::string> application_servers);
  ~AsChain();

  /// Disposition of a request. Suggests what to do next.
  enum Disposition {
    /// The request has been completely handled. Processing should
    // stop.
    Stop,

    /// The request is being passed to an external application
    // server. Processing should skip to target processing,
    // omitting any subsequent stages.
    Skip,
    // @@@ in Java I'd include the target in this as a field. Need to
    // tidy up similarly somehow.

    /// The internal application server (if any) has processed the
    // message. Processing should continue with the next stage.
    Next
  };

  Disposition on_initial_request(CallServices* call_services,
                                 UASTransaction* uas_data,
                                 pjsip_msg* msg,
                                 pjsip_tx_data* tdata,
                                 target** target);

  std::string to_string() const;
  std::string served_user() const;
  const SessionCase& session_case() const;
  bool complete() const;


private:
  bool is_mmtel(CallServices* call_services);

  const SessionCase& _session_case;
  std::string _served_user;
  std::vector<std::string> _application_servers; //< List of application server URIs.
};

