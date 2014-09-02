/**
 * @file contact_filtering.cpp Contact filtering implementation.
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

#include "contact_filtering.h"
#include "constants.h"
#include "pjutils.h"
#include "sproutsasevent.h"

#include <limits>
#include <boost/algorithm/string.hpp>

// Entry point for contact filtering.  Convert the set of bindings to a set of
// Targets, applying filtering where required.
void filter_bindings_to_targets(const std::string& aor,
                                const RegStore::AoR* aor_data,
                                pjsip_msg* msg,
                                pj_pool_t* pool,
                                int max_targets,
                                TargetList& targets,
                                SAS::TrailId trail)
{
  std::vector<pjsip_accept_contact_hdr*> accept_headers;
  std::vector<pjsip_reject_contact_hdr*> reject_headers;

  // Extract all the Accept-Contact headers.
  pjsip_accept_contact_hdr* accept_header = (pjsip_accept_contact_hdr*)
    pjsip_msg_find_hdr_by_names(msg,
                                &STR_ACCEPT_CONTACT,
                                &STR_ACCEPT_CONTACT_SHORT,
                                NULL);
  while (accept_header != NULL)
  {
    accept_headers.push_back(accept_header);
    accept_header = (pjsip_accept_contact_hdr*)
      pjsip_msg_find_hdr_by_names(msg,
                                  &STR_ACCEPT_CONTACT,
                                  &STR_ACCEPT_CONTACT_SHORT,
                                  accept_header->next);
  }

  // Extract all the Reject-Contact headers.
  pjsip_reject_contact_hdr* reject_header = (pjsip_reject_contact_hdr*)
    pjsip_msg_find_hdr_by_names(msg,
                                &STR_REJECT_CONTACT,
                                &STR_REJECT_CONTACT_SHORT,
                                NULL);
  while (reject_header != NULL)
  {
    reject_headers.push_back(reject_header);
    reject_header = (pjsip_reject_contact_hdr*)
      pjsip_msg_find_hdr_by_names(msg,
                                  &STR_REJECT_CONTACT,
                                  &STR_REJECT_CONTACT_SHORT,
                                  reject_header->next);
  }

  // Maybe add an implicit filter.
  add_implicit_filters(msg,
                       pool,
                       accept_headers,
                       reject_headers);

  // Iterate over the Bindings, checking if they're valid and creating a target
  // if so.
  const RegStore::AoR::Bindings bindings = aor_data->bindings();
  int bindings_rejected_due_to_gruu = 0;
  pjsip_param* gr_param = NULL;
  std::string requri;

  if (msg->type == PJSIP_REQUEST_MSG && (msg->line.req.uri != NULL) && PJSIP_URI_SCHEME_IS_SIP(msg->line.req.uri))
  {
      gr_param = pjsip_param_find(&((pjsip_sip_uri*)msg->line.req.uri)->other_param, &STR_GR);
      requri = PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri);
  }

  if (gr_param != NULL)
  {
    LOG_DEBUG("Request-URI has 'gr' param, so GRUU matching will be done");
  }

  for (RegStore::AoR::Bindings::const_iterator binding = bindings.begin();
       binding != bindings.end();
       ++binding)
  {
    bool rejected = false;
    bool deprioritized = false;

    std::string gruu = binding->second->gruu(pool);
    if ((gr_param != NULL) && (requri != gruu))
    {
      rejected = true;
      bindings_rejected_due_to_gruu++;
      LOG_DEBUG("GRUU %s did not match Request-URI %s", gruu.c_str(), requri.c_str());
    }

    for (std::vector<pjsip_reject_contact_hdr*>::iterator reject = reject_headers.begin();
         reject != reject_headers.end() && (!rejected);
         ++reject)
    {
      if (match_feature_sets(binding->second->_params, *reject) == YES)
      {
        LOG_DEBUG("Rejecting Contact: header matching Reject-Contact header");
        // TODO SAS log.
        rejected = true;
      }
    }

    for (std::vector<pjsip_accept_contact_hdr*>::iterator accept = accept_headers.begin();
         accept != accept_headers.end() && (!rejected);
         ++accept)
    {
      MatchResult accept_rc = match_feature_sets(binding->second->_params, *accept);

      if (accept_rc == NO)
      {
        LOG_DEBUG("Rejecting Contact: header matching Accept-Contact header");
        // TODO SAS log.
        rejected = true;
      }
      else if (accept_rc == UNKNOWN)
      {
        LOG_DEBUG("Deprioritizing Contact: header matching Accept-Contact header");
        // TODO SAS log.
        deprioritized = true;
      }
    }

    // Assuming we're still allowed to use this Contact, create a target from it.
    if (!rejected)
    {
      // There's a chance the records in the store are invalid, if so we'll drop
      // the target.
      Target target;
      bool valid = binding_to_target(aor,
                                     binding->first,
                                     *binding->second,
                                     deprioritized,
                                     pool,
                                     target);
      if (valid)
      {
        targets.push_back(target);
      }
    }
  }

  if (gr_param != NULL)
  {
    LOG_DEBUG("%d of %d bindings rejected because a GRUU was specified", bindings_rejected_due_to_gruu, bindings.size());
    SAS::Event event(trail, SASEvent::GRUU_FILTERING, 0);
    event.add_static_param(bindings_rejected_due_to_gruu);
    event.add_static_param(bindings.size());
    SAS::report_event(event);
  }

  SAS::Event event(trail, SASEvent::BINDINGS_FROM_TARGETS, 0);
  event.add_static_param(targets.size());
  event.add_static_param(bindings.size());
  SAS::report_event(event);

  if (targets.empty())
  {
    SAS::Event event(trail, SASEvent::ALL_BINDINGS_FILTERED, 0);
    SAS::report_event(event);
  }

  // Prune the excess targets to prevent over-forking.
  prune_targets(max_targets, targets);
}

// Convert a binding to its equivalent Target.  This can fail if (for example),
// the stored Path headers are not valid URIs.  In this case the function returns
// false and the target parameter should not be used.
bool binding_to_target(const std::string& aor,
                       const std::string& binding_id,
                       const RegStore::AoR::Binding& binding,
                       bool deprioritized,
                       pj_pool_t* pool,
                       Target& target)
{
  bool valid = true;

  target.from_store = true;
  target.aor = aor;
  target.binding_id = binding_id;
  target.uri = PJUtils::uri_from_string(binding._uri, pool);
  target.deprioritized = deprioritized;
  target.contact_expiry = binding._expires;
  target.contact_q1000_value = binding._priority;

  if (target.uri == NULL)
  {
    LOG_WARNING("Ignoring badly formed contact URI %s for target %s",
                binding._uri.c_str(), aor.c_str());
    // TODO SAS log
    valid = false;
  }
  else
  {
    for (std::list<std::string>::const_iterator path = binding._path_headers.begin();
         path != binding._path_headers.end();
         ++path)
    {
      pjsip_uri* path_uri = PJUtils::uri_from_string(*path, pool);
      if (path_uri != NULL)
      {
        target.paths.push_back(path_uri);
      }
      else
      {
        LOG_WARNING("Ignoring contact %s for target %s because of badly formed path header %s",
                    binding._uri.c_str(), aor.c_str(), (*path).c_str());
        // TODO SAS log
        valid = false;
        break;
      }
    }
  }

  return valid;
}

// Add an automatically created feature set if none have been
// specified.
void add_implicit_filters(const pjsip_msg* msg,
                          pj_pool_t* pool,
                          std::vector<pjsip_accept_contact_hdr*>& accept_headers,
                          const std::vector<pjsip_reject_contact_hdr*>& reject_headers)
{
  if (accept_headers.empty() && reject_headers.empty())
  {
    pjsip_accept_contact_hdr* new_hdr = pjsip_accept_contact_hdr_create(pool);
    new_hdr->explicit_match = false;
    new_hdr->required_match = true;

    // Create a method feature, specifying the requests's method.
    pjsip_param* method_feature = PJ_POOL_ALLOC_T(pool, pjsip_param);
    pj_strdup(pool, &method_feature->name, &STR_METHODS);
    pj_strdup(pool, &method_feature->value, &msg->line.req.method.name);
    pj_list_insert_after(&new_hdr->feature_set, method_feature);


    // Possibly add an event feature, specifying the body of the Event: header.
    pjsip_generic_string_hdr* event_hdr = (pjsip_generic_string_hdr*)
      pjsip_msg_find_hdr_by_names(msg,
                                  &STR_EVENT,
                                  &STR_EVENT_SHORT,
                                  NULL);
    if (event_hdr != NULL)
    {
      pjsip_param* event_feature = PJ_POOL_ALLOC_T(pool, pjsip_param);
      pj_strdup(pool, &event_feature->name, &STR_EVENTS);
      pj_strdup(pool, &event_feature->value, &event_hdr->hvalue);
      pj_list_insert_after(&new_hdr->feature_set, event_feature);
    }

    accept_headers.push_back(new_hdr);
  }
}

// Utility functions for comparing feature sets.
MatchResult match_feature_sets(const FeatureSet& contact_feature_set,
                               pjsip_accept_contact_hdr* accept)
{
  MatchResult rc = YES;

  // Iterate over the parameters on the Accept-Contact header, we can drop out
  // early if the main match value ever drops to NO since there's no way it will
  // change to UNKNOWN or YES afterwards.
  for (pjsip_param* feature_param = accept->feature_set.next;
       (feature_param != &accept->feature_set) && (rc != NO);
       feature_param = feature_param->next)
  {
    MatchResult feature_match_rc;

    // For boolean features the name may be prefixed with ! to indicate negation.
    std::string feature_name = PJUtils::pj_str_to_string(&feature_param->name);
    std::string feature_value = PJUtils::pj_str_to_unquoted_string(&feature_param->value);

    Feature feature(feature_name, feature_value);
    std::string negated_feature_name;
    if (feature_name[0] == '!')
    {
      negated_feature_name.erase(0, 1); // Drop the first character
    }
    else
    {
      negated_feature_name = "!" + feature_name;
    }

    // Now find the Contact's version of this feature (using either name).
    FeatureSet::const_iterator contact_feature;
    contact_feature = contact_feature_set.find(feature_name);
    if (contact_feature == contact_feature_set.end())
    {
      contact_feature = contact_feature_set.find(negated_feature_name);
    }

    // Now attempt to compare the two features.
    if (contact_feature == contact_feature_set.end())
    {
      // Not specified, can't say either way if the feature is a match.
      feature_match_rc = UNKNOWN;
    }
    else
    {
      feature_match_rc = match_feature(feature,
                                       *contact_feature);
    }

    // Our treatment of UNKNOWN in the feature matches is determined by
    // the explicit and required parameters on the header.
    if (feature_match_rc == UNKNOWN)
    {
      if (accept->explicit_match)
      {
        if (accept->required_match)
        {
          rc = NO;
        }
        else
        {
          rc = UNKNOWN;
        }
      }
      else
      {
        if (accept->required_match)
        {
          rc = UNKNOWN;
        }
        else
        {
          // rc is unchanged.
        }
      }
    }

    // The treatment of NO in the feature match is determined by the
    // required parameter on the header.
    if (feature_match_rc == NO)
    {
      if (accept->required_match)
      {
        rc = NO;
      }
      else
      {
        rc = UNKNOWN;
      }
    }
  }

  return rc;
}

MatchResult match_feature_sets(const FeatureSet& contact_feature_set,
                               pjsip_reject_contact_hdr* reject)
{
  MatchResult rc = YES;

  // Iterate over the parameters on the Reject-Contact header, since
  // the only way a Reject-Contact header can match is perfectly, we
  // can drop out early if rc is ever non-YES.
  for (pjsip_param* feature_param = reject->feature_set.next;
       (feature_param != &reject->feature_set) && (rc == YES);
       feature_param = feature_param->next)
  {
    // For boolean features the name may be prefixed with ! to
    // indicate negation.
    std::string feature_name = PJUtils::pj_str_to_string(&feature_param->name);
    std::string feature_value = PJUtils::pj_str_to_unquoted_string(&feature_param->value);

    Feature feature(feature_name, feature_value);
    std::string negated_feature_name;
    if (feature_name[0] == '!')
    {
      negated_feature_name.erase(0, 1); // Drop the first character
    }
    else
    {
      negated_feature_name = "!" + feature_name;
    }

    // Now find the Contact's version of this feature (using either name).
    FeatureSet::const_iterator contact_feature;
    contact_feature = contact_feature_set.find(feature_name);
    if (contact_feature == contact_feature_set.end())
    {
      contact_feature = contact_feature_set.find(negated_feature_name);
    }

    // Now attempt to compare the two features.
    if (contact_feature == contact_feature_set.end())
    {
      // Not specified, can't say either way if the feature is a match.
      rc = UNKNOWN;
    }
    else
    {
      rc = match_feature(feature,
                         *contact_feature);
    }
  }

  // Reject-Contact filters are always YES or NO.
  if (rc == UNKNOWN)
  {
    rc = NO;
  }

  return rc;
}

MatchResult match_feature(const Feature& matcher,
                          const Feature& matchee)
{
  MatchResult rc;

  // Start off with boolean features (these have no value)
  if (matcher.second.empty())
  {
    if (!matchee.second.empty())
    {
      // Matcher says boolean, matchee says valued... can't compare
      rc = UNKNOWN;
    }
    else
    {
      // Compare the names (this distinguishes between !name and name).
      if (matcher.first == matchee.first)
      {
        rc = YES;
      }
      else
      {
        rc = NO;
      }
    }
  }
  else if (matchee.second.empty())
  {
    // Matchee is boolean but matcher is not.   Can't compare.
    rc = UNKNOWN;
  }
  else if (matcher.second[0] == '<')
  {
    // Matcher is checking for string literal...
    if (matchee.second[0] == '<')
    {
      // ...as is the matchee
      if (matcher.second == matchee.second)
      {
        rc = YES;
      }
      else
      {
        rc = NO;
      }
    }
    else
    {
      // ...but matchee isn't
      rc = UNKNOWN;
    }
  }
  else if (matcher.second[0] == '#')
  {
    // Matcher is looking for a numeric predicate...
    if (matchee.second[0] == '#')
    {
      // ...as is the matchee
      rc = match_numeric(matcher.second, matchee.second);
    }
    else
    {
      // ...but the matchee is not
      rc = UNKNOWN;
    }
  }
  else
  {
    // Matcher is a token set...
    if ((matchee.second[0] == '#') ||
        (matchee.second[0] == '<'))
    {
      // ...but the matchee is not
      rc = UNKNOWN;
    }
    else
    {
      rc = match_tokens(matcher.second, matchee.second);
    }
  }

  return rc;
}

// Represents a NumericFeature
struct NumericRange
{
  float minimum;
  float maximum;

  NumericRange(const std::string& str)
  {
    if (sscanf(str.c_str(), "#%f:%f", &minimum, &maximum) == 2)
    {
      if (minimum > maximum)
      {
        throw FeatureParseError();
      }
    }
    else if (sscanf(str.c_str(), "#>=%f", &minimum) == 1)
    {
      maximum = std::numeric_limits<float>::max();
    }
    else if (sscanf(str.c_str(), "#<=%f", &maximum) == 1)
    {
      minimum = std::numeric_limits<float>::min();
    }
    else if (sscanf(str.c_str(), "#%f", &minimum) == 1)
    {
      maximum = minimum;
    }
    else
    {
      // Invalid format for numeric.
      throw FeatureParseError();
    }
  }
};

// Compare two numeric features to see if the matcher matches the matchee.
MatchResult match_numeric(const std::string& matcher,
                          const std::string& matchee)
{
  NumericRange matcher_range(matcher);
  NumericRange matchee_range(matchee);
  MatchResult rc;

  if (matcher_range.minimum <= matchee_range.minimum)
  {
    if (matcher_range.maximum >= matchee_range.maximum)
    {
      rc = YES;
    }
    else if (matcher_range.maximum >= matchee_range.minimum)
    {
      rc = UNKNOWN;
    }
    else
    {
      rc = NO;
    }
  }
  else if (matcher_range.minimum <= matchee_range.maximum)
  {
    rc = UNKNOWN;
  }
  else
  {
    rc = NO;
  }

  return rc;
}

// Only needed for passing in to "transform" below.
std::string string_to_lowercase(std::string& str)
{
  ::boost::algorithm::to_lower(str);
  return str;
}

MatchResult match_tokens(const std::string& matcher,
                         const std::string& matchee)
{
  // Convert both strings to lists of tokens
  std::vector<std::string> matcher_tokens;
  Utils::split_string(matcher, ',', matcher_tokens, 0, true);
  std::vector<std::string> matchee_tokens;
  Utils::split_string(matchee, ',', matchee_tokens, 0, true);

  // Lower-case everything so we can safely compare.
  std::transform(matcher_tokens.begin(), matcher_tokens.end(),
                 matcher_tokens.begin(), string_to_lowercase);
  std::transform(matchee_tokens.begin(), matchee_tokens.end(),
                 matchee_tokens.begin(), string_to_lowercase);

  // Sort the lists (so we can use set_intersection later)
  std::sort(matcher_tokens.begin(), matcher_tokens.end());
  std::sort(matchee_tokens.begin(), matchee_tokens.end());

  // Find the intersection.  The API for set_intersection makes no
  // sense.  Basically you pass it two ordered ranges and a start
  // point for output and it writes matching entries into the output
  // interator.  It returns the end iterator for what it wrote out so
  // you can resize() down to just the intersection (as we do) and
  // then check the length to see if the intersection was non-empty.
  std::vector<std::string> intersection(matcher_tokens.size() +
                                        matchee_tokens.size());
  std::vector<std::string>::iterator it;
  it = std::set_intersection(matcher_tokens.begin(), matcher_tokens.end(),
                             matchee_tokens.begin(), matchee_tokens.end(),
                             intersection.begin());
  intersection.resize(it - intersection.begin());

  if (intersection.size() != 0)
  {
    return YES;
  }
  else
  {
    return NO;
  }
}

// Trim a list of targets to contain at most `max_targets`.
void prune_targets(int max_targets,
                   TargetList& targets)
{
  if (targets.size() <= (unsigned long)max_targets)
  {
    return;
  }

  // Sort the targets and truncate.
  std::sort(targets.begin(), targets.end(), compare_targets);

  // Truncate down to max_targets by creating the shortened list and
  // swapping for the passed one.
  TargetList(targets.begin(), targets.begin() + max_targets).swap(targets);
}

bool compare_targets(const Target& t1, const Target& t2)
{
  // Start by comparing "q-values", higher is better.
  if (t1.contact_q1000_value > t1.contact_q1000_value)
  {
    return true;
  }
  else if (t1.contact_q1000_value < t1.contact_q1000_value)
  {
    return false;
  }
  else
  {
    // Q-values are equal, check deprioritization.
    if (!t1.deprioritized && t2.deprioritized)
    {
      return true;
    }
    else if (t1.deprioritized && !t2.deprioritized)
    {
      return false;
    }
    else
    {
      // Q-values are equal and prioritization is equal, use the tie-breaker.
      return (t1.contact_expiry > t2.contact_expiry);
    }
  }
}
