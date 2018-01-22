/**
  * @file contact_filtering.h Contact filtering API.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
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
                                Bindings& bindings,
                                pjsip_msg* msg,
                                pj_pool_t* pool,
                                int max_targets,
                                TargetList& targets,
                                bool barred,
                                SAS::TrailId trail);
bool binding_to_target(const std::string& aor,
                       const std::string& binding_id,
                       const Binding& binding,
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
