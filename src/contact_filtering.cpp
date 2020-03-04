/**
 * @file contact_filtering.cpp Contact filtering implementation.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "contact_filtering.h"
#include "constants.h"
#include "pjutils.h"
#include "sproutsasevent.h"
#include "aor_utils.h"

#include <limits>
#include <boost/algorithm/string.hpp>

// Entry point for contact filtering.  Convert the set of bindings to a set of
// Targets, applying filtering where required.
void filter_bindings_to_targets(const std::string& aor,
                                Bindings& bindings,
                                pjsip_msg* msg,
                                pj_pool_t* pool,
                                int max_targets,
                                TargetList& targets,
                                bool barred,
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
  int bindings_rejected_due_to_gruu = 0;
  bool request_uri_is_gruu = false;
  std::string requri;

  if ((PJSIP_URI_SCHEME_IS_SIP(msg->line.req.uri) && (pjsip_param_find(&((pjsip_sip_uri*)msg->line.req.uri)->other_param, &STR_GR) != NULL)))
  {
    request_uri_is_gruu = true;
    TRC_DEBUG("Request-URI has 'gr' param, so GRUU matching will be done");
  }

  // Loop over the bindings, trying to match each.
  for (Bindings::const_iterator binding = bindings.begin();
       binding != bindings.end();
       ++binding)
  {
    TRC_DEBUG("Performing contact filtering on binding %s", binding->first.c_str());
    bool rejected = false;
    bool deprioritized = false;

    // Perform Barred filtering. If we are routing to a barred IMPU, only return
    // bindings that have an emergency registration.
    if ((barred) &&
        (!binding->second->_emergency_registration))
    {
      rejected = true;
    }

    // Perform GRUU filtering.
    if (request_uri_is_gruu)
    {
      pjsip_sip_uri* pub_gruu = AoRUtils::pub_gruu(binding->second, pool);
      if ((pub_gruu == NULL) ||
          (pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI,
                         msg->line.req.uri,
                         pub_gruu) != PJ_SUCCESS))
      {
        rejected = true;
        bindings_rejected_due_to_gruu++;
        if (pub_gruu != NULL)
        {
        TRC_DEBUG("GRUU %s did not match Request-URI %s",
                  PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, (pjsip_uri*)pub_gruu).c_str(),
                  PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri).c_str());
        }
        else
        {
        TRC_DEBUG("Binding without GRUU did not match Request-URI %s",
                  PJUtils::uri_to_string(PJSIP_URI_IN_REQ_URI, msg->line.req.uri).c_str());
        }
      }
    }

    // Perform Reject-Contact filtering.
    for (std::vector<pjsip_reject_contact_hdr*>::iterator reject = reject_headers.begin();
         reject != reject_headers.end() && (!rejected);
         ++reject)
    {
      if (match_feature_sets(binding->second->_params, *reject) == YES)
      {
        TRC_DEBUG("Rejecting Contact: header matching Reject-Contact header");
        // TODO SAS log.
        rejected = true;
      }
    }

    // Perform Accept-Contact filtering. Unlike Reject-Contact
    // headers, Accept-Contact headers have a "require" parameter,
    // which determines whetner to reject or just deprioritise
    // non-matching bindings.
    for (std::vector<pjsip_accept_contact_hdr*>::iterator accept = accept_headers.begin();
         accept != accept_headers.end() && (!rejected);
         ++accept)
    {
      MatchResult accept_rc = match_feature_sets(binding->second->_params, *accept);
      if (accept_rc == NO)
      {
        if ((*accept)->required_match) {
          TRC_DEBUG("Rejecting Contact: header matching Accept-Contact header");
          // TODO SAS log.
          rejected = true;
        }
        else
        {
          TRC_DEBUG("Deprioritizing Contact: header matching Accept-Contact header");
          // TODO SAS log.
          deprioritized = true;
        }
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

  // SAS logging now we know how many targets we have.
  if (request_uri_is_gruu)
  {
    TRC_DEBUG("%d of %d bindings rejected because a GRUU was specified", bindings_rejected_due_to_gruu, bindings.size());
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
                       const Binding& binding,
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
    TRC_WARNING("Ignoring badly formed contact URI %s for target %s",
                binding._uri.c_str(), aor.c_str());
    // TODO SAS log
    valid = false;
  }
  else
  {
    // Fill in the paths parameter for the target.
    // If _path_headers is empty no paths parameter is set.
    if (!binding._path_headers.empty())
    {
      for (std::string path : binding._path_headers)
      {
        pjsip_route_hdr* path_hdr = (pjsip_route_hdr*)pjsip_parse_hdr(pool,
                                                                      &STR_ROUTE,
                                                                      (char*)path.c_str(),
                                                                      strlen(path.c_str()),
                                                                      NULL);
        if (path_hdr != NULL)
        {
          // We need to clone the message here so that we can delete path_str.
          // If didn't clone the header we would free memory in the header when
          // deleting path_str.
          pjsip_route_hdr* path_hdr_clone = (pjsip_route_hdr*)pjsip_hdr_clone(pool, path_hdr);
          target.paths.push_back(path_hdr_clone);
        }
        else
        {
          TRC_WARNING("Ignoring contact %s for target %s because of badly formed path header %s",
                      binding._uri.c_str(), aor.c_str(), path.c_str());
          // TODO SAS log
          valid = false;
          break;
        }
      }
    }
    else
    {
      TRC_DEBUG("Empty path headers field for contact %s, implying no path "
                "headers were present on a register (which is valid)",
                binding._uri.c_str());
    }
  }

  return valid;
}

// Add an automatically created feature predicate if none have been
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

// Compares the feature predicate in the Contact header with the
// feature predicate in the Accept-Contact header. Under the RFC 3841
// logic, two feature predicates match if there is any feature
// collection which could satisfy them both. In the case of
// Accept-Contact headers, if the "explicit" parameter is set, the
// feature predicates only match if the Contact header includes all
// the features in the Accept-Contact header (i.e. the list of feature
// names in the Contact header must be a subset of the list in the
// Accept-Contact header).
MatchResult match_feature_sets(const FeatureSet& contact_feature_set,
                               pjsip_accept_contact_hdr* accept)
{
  MatchResult rc = YES;

  // Iterate over the parameters on the Accept-Contact header, we can drop out
  // early if the main match value ever drops to NO since there's no way it will
  // change to YES afterwards.
  for (pjsip_param* feature_param = accept->feature_set.next;
       (feature_param != &accept->feature_set) && (rc != NO);
       feature_param = feature_param->next)
  {
    std::string feature_name = PJUtils::pj_str_to_string(&feature_param->name);
    std::string feature_value = PJUtils::pj_str_to_string(&feature_param->value);
    TRC_DEBUG("Trying to match Accept-Contact parameter '%s' (value '%s')", feature_name.c_str(), feature_value.c_str());

    Feature feature(feature_name, feature_value);

    // Now find the Contact's version of this feature.
    FeatureSet::const_iterator contact_feature;
    contact_feature = contact_feature_set.find(feature_name);

    // Now attempt to compare the two features.
    if (contact_feature == contact_feature_set.end())
    {
      // Contact header doesn't contain a feature in the
      // Accept-Contact header - should fail the match if "explicit"
      // was specified.
      if (accept->explicit_match)
      {
        rc = NO;
        TRC_DEBUG("Parameter %s is not in the Contact parameters and is explicitly required", feature_name.c_str());
      }
      else
      {
        rc = YES;
        TRC_DEBUG("Parameter %s is not in the Contact parameters but is not explicitly required", feature_name.c_str());
      }
    }
    else
    {
      rc = match_feature(feature,
                         *contact_feature);
    }
  }

  return rc;
}

// Compares the feature predicate in the Reject-Contact header with the
// feature predicate in the Accept-Contact header. Under the RFC 3841
// logic, two feature predicates match if there is any feature
// collection which could satisfy them both.
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
    std::string feature_name = PJUtils::pj_str_to_string(&feature_param->name);
    std::string feature_value = PJUtils::pj_str_to_string(&feature_param->value);
    TRC_DEBUG("Trying to match Reject-Contact parameter '%s' (value '%s')", feature_name.c_str(), feature_value.c_str());

    Feature feature(feature_name, feature_value);

    // Now find the Contact's version of this feature.
    FeatureSet::const_iterator contact_feature;
    contact_feature = contact_feature_set.find(feature_name);

    // Now attempt to compare the two features.
    if (contact_feature == contact_feature_set.end())
    {
      // The Contact header doesn't contain this feature tag, so this
      // Reject-Contact predicate is discarded.
      rc = NO;
      TRC_DEBUG("Parameter %s is not in the Contact parameters", feature_name.c_str());
    }
    else
    {
      rc = match_feature(feature,
                         *contact_feature);
    }
  }

  return rc;
}

// Compares a single term of a feature predicate in the
// Accept/Reject-Contact header (the matcher) and in the Contact
// header (the matchee).
MatchResult match_feature(Feature matcher,
                          Feature matchee)
{
  MatchResult rc;
  TRC_DEBUG("Matching parameter '%s' - Accept-Contact/Reject-Contact value '%s', Contact value '%s'",
            matcher.first.c_str(),
            matcher.second.c_str(),
            matchee.second.c_str());

  // Features with no value are boolean terms, equivalent to "TRUE"
  // according to RFC 3841.
  if (matcher.second.empty())
  {
    matcher.second = "TRUE";
  }

  if (matchee.second.empty())
  {
    matchee.second = "TRUE";
  }

  // Unquote the values, as they don't matter.
  if ((matcher.second.front() == '"') && (matcher.second.back() == '"'))
  {
    matcher.second = matcher.second.substr(1, (matcher.second.size() - 2));
  }
  if ((matchee.second.front() == '"') && (matchee.second.back() == '"'))
  {
    matchee.second = matchee.second.substr(1, (matchee.second.size() - 2));
  }

  if (matcher.second[0] == '<')
  {
    // Matcher is checking for string literal...
    if (matchee.second[0] == '<')
    {
      // ...as is the matchee...
      if (matcher.second == matchee.second)
      {
        // ...and it's the same string literal
        rc = YES;
      }
      else
      {
        // ...but it's a different string literal
        rc = NO;
      }
    }
    else
    {
      // ...but matchee isn't, so no possible feature collection could
      // match both
      rc = NO;
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
      // The two feature predicates each require a term of different
      // types, so no feature collection can match both.
      rc = NO;
    }
  }
  else
  {
    // Matcher is a token set...
    if ((matchee.second[0] == '#') ||
        (matchee.second[0] == '<'))
    {
      // The two feature predicates each require a term of different
      // types, so no feature collection can match both.
      rc = NO;
    }
    else
    {
      rc = match_tokens(matcher.second, matchee.second);
    }
  }

  if (rc == NO)
  {
    TRC_DEBUG("No possible feature collection could match this parameter in both feature predicates");
  }
  else if (rc == YES)
  {
    TRC_DEBUG("A feature collection could match this parameter in both feature predicates");
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
    // RCC.07 v9.0 section Chatbot Feature Tags, Chatbot Application Version, Section 3.6.2.2
    // Add support for an = as part of the version designation.
    else if (sscanf(str.c_str(), "#=%f", &minimum) == 1)
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
      rc = YES;
    }
    else
    {
      rc = NO;
    }
  }
  else if (matcher_range.minimum <= matchee_range.maximum)
  {
    rc = YES;
  }
  else
  {
    rc = NO;
  }

  return rc;
}

// Only needed for passing in to "transform" below.
std::string string_to_lowercase_and_trim(std::string& str)
{
  ::boost::algorithm::to_lower(str);
  return Utils::trim(str);
}

MatchResult match_tokens(const std::string& matcher,
                         const std::string& matchee)
{
  // Convert both strings to lists of tokens
  std::vector<std::string> matcher_tokens;
  Utils::split_string(matcher, ',', matcher_tokens, 0, true);
  std::vector<std::string> matchee_tokens;
  Utils::split_string(matchee, ',', matchee_tokens, 0, true);

  // Lower-case everything and strip whitespace so we can safely compare.
  std::transform(matcher_tokens.begin(), matcher_tokens.end(),
                 matcher_tokens.begin(), string_to_lowercase_and_trim);
  std::transform(matchee_tokens.begin(), matchee_tokens.end(),
                 matchee_tokens.begin(), string_to_lowercase_and_trim);

  // Loop over both sets of tokens, to see whether a feature
  // collection (i.e. a single token) could satisfy both predicates.
  // Specifically, we want:
  // * any token that is in both lists, or
  // * any negation (i.e. !X, which in this context means "anything
  // but X") and any token in the other list which matches that
  // negation (i.e. anything but X, or any other negation).
  for (std::vector<std::string>::iterator token1 = matcher_tokens.begin();
       token1 != matcher_tokens.end();
       token1++)
  {
    for (std::vector<std::string>::iterator token2 = matchee_tokens.begin();
         token2 != matchee_tokens.end();
         token2++)
    {
      if (*token1 == *token2)
      {
        // We match if there is any overlap between the two sets.
        return YES;
      }

      // One token is a negation, ie. !X. If the other token is not
      // equal to X, then that token satisfies both feature predicates.
      if ((*token1)[0] == '!')
      {
        std::string token1_without_negation = token1->substr(1, std::string::npos);
        TRC_DEBUG("Comparing negation of %s to %s", token1_without_negation.c_str(), token2->c_str());
        if (token1_without_negation != *token2)
        {
          return YES;
        }
      }

      if ((*token2)[0] == '!')
      {
        std::string token2_without_negation = token2->substr(1, std::string::npos);
        TRC_DEBUG("Comparing negation of %s to %s", token2_without_negation.c_str(), token1->c_str());
        if (token2_without_negation != *token1)
        {
          return YES;
        }
      }
    }
  }

  return NO;
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
  if (t1.contact_q1000_value > t2.contact_q1000_value)
  {
    return true;
  }
  else if (t1.contact_q1000_value < t2.contact_q1000_value)
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
