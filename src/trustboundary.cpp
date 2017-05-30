/**
 * @file trustboundary.cpp Trust boundary processing
 *
 * Copyright (C) Metaswitch Networks 2015
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */


extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}

#include <string>

#include "log.h"
#include "constants.h"
#include "pjutils.h"
#include "custom_headers.h"
#include "trustboundary.h"
#include "stack.h"

/// Strip headers as appropriate when crossing a trust boundary.
static void proxy_strip_trusted(pjsip_tx_data *tdata)
{
  TRC_DEBUG("Strip trusted headers");

  PJUtils::remove_hdr(tdata->msg, &STR_P_A_N_I);
  PJUtils::remove_hdr(tdata->msg, &STR_P_V_N_I);
  PJUtils::remove_hdr(tdata->msg, &STR_P_SERVED_USER);
  pjsip_msg_find_remove_hdr(tdata->msg, PJSIP_H_AUTHORIZATION, NULL);
  pjsip_msg_find_remove_hdr(tdata->msg, PJSIP_H_PROXY_AUTHORIZATION, NULL);
}

/// Add P-Charging headers on incoming out-of-dialog/dialog initiating requests
static void proxy_add_p_charging_header(pjsip_tx_data *tdata)
{
  TRC_DEBUG("Add P-Charging headers");

  std::string cdf_domain = PJUtils::pj_str_to_string(&stack_data.cdf_domain);

  if (cdf_domain != "")
  {
    // Add the P-Charging-Function-Addresses. The value of the CDF is passed in
    // as a parameter in bono - if this isn't present then don't set these
    // headers.
    pjsip_p_c_f_a_hdr* p_c_f_a = pjsip_p_c_f_a_hdr_create(tdata->pool);
    pjsip_param* new_param = (pjsip_param*) pj_pool_alloc(tdata->pool, sizeof(pjsip_param));
    new_param->name = STR_CCF;
    new_param->value = stack_data.cdf_domain;

    pj_list_insert_before(&p_c_f_a->ccf, new_param);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)p_c_f_a);

    // Add the P-Charging-Vector Id. The icid-value is the Call-ID, and the
    // icid-generated-at is the bono hostname - it must be unique to the node that
    // generates it.
    pjsip_cid_hdr* call_id = (pjsip_cid_hdr*)pjsip_msg_find_hdr_by_name(tdata->msg,
                                                                        &STR_CALL_ID,
                                                                        NULL);
    std::string c_id = PJUtils::pj_str_to_string(&call_id->id);
    c_id.erase(std::remove(c_id.begin(), c_id.end(), '@'), c_id.end());
    c_id.erase(std::remove(c_id.begin(), c_id.end(), '"'), c_id.end());

    pjsip_p_c_v_hdr* p_c_v = pjsip_p_c_v_hdr_create(tdata->pool);

    pj_strdup2(tdata->pool, &p_c_v->icid, c_id.c_str());
    p_c_v->icid_gen_addr = stack_data.public_host;

    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)p_c_v);
  }
}

TrustBoundary::TrustBoundary(std::string description,
                             pj_bool_t strip_request,
                             pj_bool_t strip_response,
                             pj_bool_t strip_p_charging,
                             pj_bool_t add_p_charging,
                             pj_bool_t add_p_charging_rsp) :
  _strip_request(strip_request),
  _strip_response(strip_response),
  _strip_p_charging(strip_p_charging),
  _add_p_charging(add_p_charging),
  _add_p_charging_rsp(add_p_charging_rsp),
  _description(description)
{
  if ((_add_p_charging && !_strip_p_charging) ||
      (_add_p_charging_rsp && !_strip_request))
  {
    // LCOV_EXCL_START
    TRC_ERROR("Trust boundary configured to add P-Charging headers without stripping existing ones, inconsistent configuration");
    _strip_p_charging = PJ_TRUE;
    // LCOV_EXCL_STOP
  }
}

void TrustBoundary::process_request(pjsip_tx_data* tdata)
{
  if (_strip_request)
  {
    proxy_strip_trusted(tdata);
  }

  if (_strip_p_charging)
  {
    PJUtils::remove_hdr(tdata->msg, &STR_P_C_V);
    PJUtils::remove_hdr(tdata->msg, &STR_P_C_F_A);
  }

  if (_add_p_charging)
  {
    proxy_add_p_charging_header(tdata);
  }
}

void TrustBoundary::process_response(pjsip_tx_data* tdata)
{
  if (_strip_response)
  {
    proxy_strip_trusted(tdata);
  }

  if(_strip_p_charging)
  {
    PJUtils::remove_hdr(tdata->msg, &STR_P_C_V);
    PJUtils::remove_hdr(tdata->msg, &STR_P_C_F_A);
  }

  if (_add_p_charging_rsp)
  {
    proxy_add_p_charging_header(tdata);
  }
}

void TrustBoundary::process_stateless_message(pjsip_tx_data* tdata)
{
  TRC_DEBUG("Strip trusted headers - stateless");
  proxy_strip_trusted(tdata);
}

std::string TrustBoundary::to_string()
{
  return _description + "(" + (_strip_request  ? "-req" : "") +
                        "," + (_strip_response ? "-rsp" : "") +
                        "," + (_add_p_charging ? "-pch" : "") + ")";
}

/// Trust boundary instance: no boundary;
TrustBoundary TrustBoundary::TRUSTED("TRUSTED", false, false, false, false, false);

/// Trust boundary instance: from client to core.  Allow client to
/// provide trusted data to the core, but don't allow it to see
/// the core's internal data. I.e., strip from responses.
TrustBoundary TrustBoundary::INBOUND_EDGE_CLIENT("INBOUND_EDGE_CLIENT", false, true, true, true, false);

/// Trust boundary instance: from core to client.  Allow client to
/// provide trusted data to the core, but don't allow it to see
/// the core's internal data. I.e., strip from requests.
TrustBoundary TrustBoundary::OUTBOUND_EDGE_CLIENT("OUTBOUND_EDGE_CLIENT", true, false, true, false, true);

/// Trust boundary instance: edge processing, but we don't know which
/// direction. Don't allow trusted data to pass in either direction.
TrustBoundary TrustBoundary::UNKNOWN_EDGE_CLIENT("UNKNOWN_EDGE_CLIENT", true, true, true, false, false);

/// Trust boundary instance: from trunk to core.  Don't allow
/// trusted data to pass in either direction.
TrustBoundary TrustBoundary::INBOUND_TRUNK("INBOUND_TRUNK", true, true, true, true, false);

/// Trust boundary instance: from core to trunk.  Don't allow
/// trusted data to pass in either direction.
TrustBoundary TrustBoundary::OUTBOUND_TRUNK("OUTBOUND_TRUNK", true, true, true, false, true);

