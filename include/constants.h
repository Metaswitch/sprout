/**
 * @file constants.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

extern "C" {
#include <pjsip.h>
}

const pj_str_t STR_HISTORY_INFO = pj_str((char*)"History-Info");
const pj_str_t STR_DIVERSION = pj_str((char *)"Diversion");
const pj_str_t STR_SUPPORTED = pj_str((char *)"Supported");
const pj_str_t STR_REQUIRE = pj_str((char *)"Require");
const pj_str_t STR_PATH = pj_str((char *)"Path");
const pj_str_t STR_OUTBOUND = pj_str((char *)"outbound");
const pj_str_t STR_PARAM_OB = pj_str((char *)"ob");
const pj_str_t STR_SIP_INSTANCE = pj_str((char *)"+sip.instance");
const pj_str_t STR_REG_ID = pj_str((char *)"reg-id");
const pj_str_t STR_OB = pj_str((char *)"ob");
const pj_str_t STR_INTEGRITY_PROTECTED = pj_str((char *)"integrity-protected");
const pj_str_t STR_YES = pj_str((char *)"yes");
const pj_str_t STR_NO = pj_str((char *)"no");
const pj_str_t STR_TLS_YES = pj_str((char *)"tls-yes");
const pj_str_t STR_TLS_PENDING = pj_str((char *)"tls-pending");
const pj_str_t STR_IP_ASSOC_YES = pj_str((char *)"ip-assoc-yes");
const pj_str_t STR_IP_ASSOC_PENDING = pj_str((char *)"ip-assoc-pending");
const pj_str_t STR_AUTH_DONE = pj_str((char *)"auth-done");
const pj_str_t STR_PRIVACY = pj_str((char *)"Privacy");
const pj_str_t STR_P_A_N_I = pj_str((char *)"P-Access-Network-Info");
const pj_str_t STR_P_V_N_I = pj_str((char *)"P-Visited-Network-ID");
const pj_str_t STR_P_SERVED_USER = pj_str((char*)"P-Served-User");
const pj_str_t STR_P_ASSERTED_IDENTITY = pj_str((char*)"P-Asserted-Identity");
const pj_str_t STR_P_PREFERRED_IDENTITY = pj_str((char*)"P-Preferred-Identity");
const pj_str_t STR_P_ASSOCIATED_URI = pj_str((char*)"P-Associated-URI");
const pj_str_t STR_REQUEST_DISPOSITION = pj_str((char*)"Request-Disposition");
const pj_str_t STR_SERVICE_ROUTE = pj_str((char*)"Service-Route");
const pj_str_t STR_IN_REPLY_TO = pj_str((char*)"In-Reply-To");
const pj_str_t STR_ORIG = pj_str((char*)"orig");
const pj_str_t STR_ORIG_CDIV = pj_str((char*)"orig-cdiv");
const pj_str_t STR_NO_FORK = pj_str((char*)"no-fork");
const pj_str_t STR_P_C_V = pj_str((char*)"P-Charging-Vector");
const pj_str_t STR_P_C_F_A = pj_str((char*)"P-Charging-Function-Addresses");
const pj_str_t STR_P_CALLED_PARTY_ID = pj_str((char*)"P-Called-Party-ID");
const pj_str_t STR_DIGEST = pj_str((char*)"Digest");
const pj_str_t STR_MD5 = pj_str((char*)"MD5");
const pj_str_t STR_AKAV1_MD5 = pj_str((char*)"AKAv1-MD5");
const pj_str_t STR_AKAV2_MD5 = pj_str((char*)"AKAv2-MD5");
const pj_str_t STR_AUTH = pj_str((char*)"auth");
const pj_str_t STR_AUTS = pj_str((char*)"auts");
const pj_str_t STR_CK = pj_str((char*)"ck");
const pj_str_t STR_IK = pj_str((char*)"ik");
const pj_str_t STR_P_PROFILE_KEY = pj_str((char*)"P-Profile-Key");
const pj_str_t STR_APPLICATION = pj_str((char*)"application");
const pj_str_t STR_JSON = pj_str((char*)"json");
const pj_str_t STR_SDP = pj_str((char*)"sdp");
const pj_str_t STR_TEXT = pj_str((char*)"text");
const pj_str_t STR_XML = pj_str((char*)"xml");
const pj_str_t STR_EVENT = pj_str((char*)"Event");
const pj_str_t STR_EVENT_LOWER = pj_str((char*)"event");
const pj_str_t STR_EVENTS = pj_str((char*)"events");
const pj_str_t STR_EVENT_SHORT = pj_str((char*)"o");
const pj_str_t STR_X = pj_str((char*)"X");
const pj_str_t STR_REASON = pj_str((char*)"Reason");
const pj_str_t STR_TRANSIT_IOI = pj_str((char*)"transit-ioi");
const pj_str_t STR_SESSION_EXPIRES = pj_str((char*)"Session-Expires");
const pj_str_t STR_MIN_SE = pj_str((char*)"Min-SE");
const pj_str_t STR_CALL_ID = pj_str((char*)"Call-ID");
const pj_str_t STR_CCF = pj_str((char*)"ccf");
const pj_str_t STR_ECF = pj_str((char*)"ecf");
const pj_str_t STR_CONTENT_DISPOSITION = pj_str((char*)"Content-Disposition");
const pj_str_t STR_REG = pj_str((char*)"reg");
const pj_str_t STR_SOS = pj_str((char*)"sos");
const pj_str_t STR_USER = pj_str((char*)"user");
const pj_str_t STR_CHARGE_ORIG = pj_str((char*)"charge-orig");
const pj_str_t STR_CHARGE_TERM = pj_str((char*)"charge-term");
const pj_str_t STR_CHARGE_NONE = pj_str((char*)"charge-none");
const pj_str_t STR_METHODS = pj_str((char*)"methods");
const pj_str_t STR_ACCEPT_CONTACT = pj_str((char*)"Accept-Contact");
const pj_str_t STR_ACCEPT_CONTACT_SHORT = pj_str((char*)"a");
const pj_str_t STR_REJECT_CONTACT = pj_str((char*)"Reject-Contact");
const pj_str_t STR_REJECT_CONTACT_SHORT = pj_str((char*)"j");
const pj_str_t STR_ALLOW_EVENTS = pj_str((char*)"Allow-Events");
const pj_str_t STR_SESCASE = pj_str((char*)"sescase");
const pj_str_t STR_BILLING_ROLE = pj_str((char*)"billing-role");
const pj_str_t STR_GR = pj_str((char*)"gr");
const pj_str_t STR_XML_PUB_GRUU = pj_str((char*)"gr:pub-gruu");
const pj_str_t STR_ISUB = pj_str((char*)"isub");
const pj_str_t STR_EXT = pj_str((char*)"ext");
const pj_str_t STR_USER_PHONE = pj_str((char*)"phone");
const pj_str_t STR_DIALOG_ID = pj_str((char*)"dialog_id");
const pj_str_t STR_TARGET = pj_str((char*)"target");
const pj_str_t STR_CONDITIONS = pj_str((char*)"conditions");
const pj_str_t STR_NO_REPLY_TIMER = pj_str((char*)"no-reply-timer");
const pj_str_t STR_NPDI = pj_str((char*)"npdi");
const pj_str_t STR_RN = pj_str((char*)"rn");
const pj_str_t STR_AUTO_REG = pj_str((char*)"auto-reg");
const pj_str_t STR_TIMER = pj_str((char*)"timer");
const pj_str_t STR_TO = pj_str((char*)"To");
const pj_str_t STR_FROM = pj_str((char*)"From");
const pj_str_t STR_ROUTE = pj_str((char*)"Route");
const pj_str_t STR_CONTENT_TYPE = pj_str((char*)"Content-Type");
const pj_str_t STR_CONTENT_LENGTH = pj_str((char*)"Content-Length");
const pj_str_t STR_SERVICE = pj_str((char*)"service");
const pj_str_t STR_USERNAME = pj_str((char*)"username");
const pj_str_t STR_NONCE = pj_str((char*)"nonce");
const pj_str_t STR_NAMESPACE = pj_str((char*)"namespace");
const pj_str_t STR_MMFTARGET = pj_str((char*)"mmftarget");
const pj_str_t STR_MMFSCOPE = pj_str((char*)"mmfscope");

/// Prefix of ODI tokens we generate.
const pj_str_t STR_ODI_PREFIX = pj_str((char*)"odi_");

const int SIP_STATUS_FLOW_FAILED = 430;
const pj_str_t SIP_REASON_FLOW_FAILED = pj_str((char*)"Flow failed");
const pj_str_t SIP_REASON_ENUM_FAILED = pj_str((char*)"ENUM translation failed");
const pj_str_t SIP_REASON_OFFNET_DISALLOWED = pj_str((char*)"Off-net calling not allowed");
const pj_str_t SIP_REASON_ADDR_INCOMPLETE = pj_str((char*)"Address Incomplete");

/// Constants for generating notify bodies.

// MIME
const pj_str_t STR_MIME_TYPE = pj_str((char*)"application");
const pj_str_t STR_MIME_SUBTYPE = pj_str((char*)"reginfo+xml");

/* XML node name constants */
const pj_str_t STR_REGISTRATION = pj_str((char*)"registration");
const pj_str_t STR_CONTACT = pj_str((char*)"contact");
const pj_str_t STR_URI = pj_str((char*)"uri");
const pj_str_t STR_WILDCARD = pj_str((char*)"ere:wildcardedIdentity");
const pj_str_t STR_UNKNOWN_PARAM = pj_str((char*)"unknown-param");

/* XML node attribute constants */
const pj_str_t STR_STATE = pj_str((char*)"state");
const pj_str_t STR_AOR = pj_str((char*)"aor");
const pj_str_t STR_ID = pj_str((char*)"id");
const pj_str_t STR_NAME = pj_str((char*)"name");

/* XML node registration STATE attribute enum constants. */
const pj_str_t STR_INIT = pj_str((char*)"init");
const pj_str_t STR_ACTIVE = pj_str((char*)"active");
const pj_str_t STR_TERMINATED = pj_str((char*)"terminated");

/* XML node doc STATE attribute enum constants. */
const pj_str_t STR_FULL = pj_str((char*)"full");
const pj_str_t STR_PARTIAL = pj_str((char*)"partial");

/* XML node EVENT attribute enum constants. */
const pj_str_t STR_REGISTERED = pj_str((char*)"registered");
const pj_str_t STR_CREATED = pj_str((char*)"created");
const pj_str_t STR_REFRESHED = pj_str((char*)"refreshed");
const pj_str_t STR_EXPIRED = pj_str((char*)"expired");
const pj_str_t STR_DEACTIVATED = pj_str((char*)"deactivated");
const pj_str_t STR_SHORTENED = pj_str((char*)"shortened");
const pj_str_t STR_UNREGISTERED = pj_str((char*)"unregistered");
const pj_str_t STR_TIMEOUT = pj_str((char*)"timeout");

/* XML attributes constants */
const pj_str_t STR_REGINFO = pj_str((char*)"reginfo");
const pj_str_t STR_XMLNS_NAME = pj_str((char*)"xmlns");
const pj_str_t STR_XMLNS_VAL = pj_str((char*)"urn:ietf:params:xml:ns:reginfo");
const pj_str_t STR_XMLNS_GRUU_NAME = pj_str((char*)"xmlns:gr");
const pj_str_t STR_XMLNS_GRUU_VAL = pj_str((char*)"urn:ietf:params:xml:ns:gruuinfo");
const pj_str_t STR_VERSION = pj_str((char*)"version");
const pj_str_t STR_VERSION_VAL = pj_str((char*)"0");
const pj_str_t STR_XMLNS_XSI_NAME = pj_str((char*)"xmlns:xsi");
const pj_str_t STR_XMLNS_XSI_VAL = pj_str((char*)"http://www.w3.org/2001/XMLSchema-instance");
const pj_str_t STR_XMLNS_ERE_NAME  = pj_str((char*)"xmlns:ere");
const pj_str_t STR_XMLNS_ERE_VAL = pj_str((char*)"urn:3gpp:ns:extRegExp:1.0");

// XML schema location
const pj_str_t STR_XSI_SLOC_NAME = pj_str((char*)"xsi:schemaLocation");
const pj_str_t STR_XSI_SLOC_VAL = pj_str((char*)"http://www.w3.org/2001/03/xml.xsd");

// SIP methods not defined in PJSIP core.
const static pjsip_method METHOD_UPDATE = { PJSIP_OTHER_METHOD, pj_str((char*)"UPDATE") };
const static pjsip_method METHOD_INFO = { PJSIP_OTHER_METHOD, pj_str((char*)"INFO") };

#endif /* CONSTANTS_H_ */
