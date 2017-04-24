/**
  * @file contact_filtering.h Contact filtering API.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
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

#ifndef CONTACT_FILTERING_H__
#define CONTACT_FILTERING_H__

#include "subscriber_data_manager.h"
#include "aschain.h"
#include "custom_headers.h"

typedef std::map<std::string, std::string> FeatureSet;
typedef std::pair<const std::string, std::string> Feature;

// Exception thrown if a feature rule doesn't parse
class FeatureParseError {};

// Entry point for contact filtering.  Convert the set of bindings to a set of
// Targets, applying filtering where required.
void filter_bindings_to_targets(const std::string& aor,
                                const SubscriberDataManager::AoR* bindings,
                                pjsip_msg* msg,
                                pj_pool_t* pool,
                                int max_targets,
                                TargetList& targets,
                                bool barred,
                                SAS::TrailId trail);
bool binding_to_target(const std::string& aor,
                       const std::string& binding_id,
                       const SubscriberDataManager::AoR::Binding& binding,
                       bool deprioritized,
                       pj_pool_t* pool,
                       Target& target);

// Add an automatically created feature set if none have been
// specified.
void add_implicit_filters(const pjsip_msg* msg,
                          pj_pool_t* pool,
                          std::vector<pjsip_accept_contact_hdr*>& accept_contacts,
                          const std::vector<pjsip_reject_contact_hdr*>& reject_contacts);

// Utility functions for comparing feature sets.
enum MatchResult { YES, NO };
MatchResult match_feature_sets(const FeatureSet& contact_filter_set,
                               pjsip_accept_contact_hdr* accept);
MatchResult match_feature_sets(const FeatureSet& contact_filter_set,
                               pjsip_reject_contact_hdr* reject);
MatchResult match_feature(Feature matcher,
                          Feature matchee);
MatchResult match_numeric(const std::string& matcher,
                          const std::string& matchee);
MatchResult match_tokens(const std::string& matcher,
                         const std::string& matchee);

// Trim a list of targets to contain at most `max_targets`.
void prune_targets(int max_targets,
                   TargetList& targets);
bool compare_targets(const Target& t1, const Target& t2);

#endif
