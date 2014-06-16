/**
 * @file custom_headers_test.cpp UT for custom header parsers.
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2013  Metaswitch Networks Ltd
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
#include <gtest/gtest.h>

#include "siptest.hpp"
#include "pjutils.h"
#include "stack.h"
#include "fakelogger.hpp"
#include "custom_headers.h"

using namespace std;

#define EXPECT_PJEQ(X, Y) EXPECT_EQ(PJUtils::pj_str_to_string(&X), string(Y))

/// Fixture for Custom Header testing
class CustomHeadersTest : public SipTest
{
public:
  static void SetUpTestCase()
  {
    SipTest::SetUpTestCase();
  }

  static void TearDownTestCase()
  {
    SipTest::TearDownTestCase();
  }
};

TEST_F(CustomHeadersTest, PChargingVector)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=4815162542; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Charging-Vector");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                          &header_name,
                                                          NULL);
  EXPECT_NE(hdr, (pjsip_hdr*)NULL);

  // We have a P-CV header, check it was filled out correctly.
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)hdr;

  EXPECT_PJEQ(pcv->icid, "4815162542");
  EXPECT_PJEQ(pcv->orig_ioi, "homedomain");
  EXPECT_PJEQ(pcv->term_ioi, "remotedomain");
  EXPECT_PJEQ(pcv->icid_gen_addr, "edge.proxy.net");
  EXPECT_EQ(1u, pj_list_size(&pcv->other_param));

  // Test the VPTR functions (clone, shallow clone and print on).
  pjsip_p_c_v_hdr* pcv_clone = (pjsip_p_c_v_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);

  EXPECT_PJEQ(pcv_clone->icid, "4815162542");
  EXPECT_PJEQ(pcv_clone->orig_ioi, "homedomain");
  EXPECT_PJEQ(pcv_clone->term_ioi, "remotedomain");
  EXPECT_PJEQ(pcv_clone->icid_gen_addr, "edge.proxy.net");
  EXPECT_EQ(1u, pj_list_size(&pcv_clone->other_param));

  pjsip_p_c_v_hdr* pcv_sclone = (pjsip_p_c_v_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);

  EXPECT_PJEQ(pcv_sclone->icid, "4815162542");
  EXPECT_PJEQ(pcv_sclone->orig_ioi, "homedomain");
  EXPECT_PJEQ(pcv_sclone->term_ioi, "remotedomain");
  EXPECT_PJEQ(pcv_sclone->icid_gen_addr, "edge.proxy.net");
  EXPECT_EQ(1u, pj_list_size(&pcv_sclone->other_param));

  char buf[1024];
  hdr = (pjsip_hdr*)pcv_clone;
  int written = hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 140);
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"4815162542\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(CustomHeadersTest, PChargingVectorQuotedIcidValue)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"

             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=\"4815162542\"; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str);

  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Charging-Vector");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                          &header_name,
                                                          NULL);
  EXPECT_NE(hdr, (pjsip_hdr*)NULL);

  // We have a P-CV header, check it was filled out correctly and the quotes were stripped
  pjsip_p_c_v_hdr* pcv = (pjsip_p_c_v_hdr*)hdr;

  EXPECT_PJEQ(pcv->icid, "4815162542");
  EXPECT_PJEQ(pcv->orig_ioi, "homedomain");
  EXPECT_PJEQ(pcv->term_ioi, "remotedomain");
  EXPECT_PJEQ(pcv->icid_gen_addr, "edge.proxy.net");
  EXPECT_EQ(1u, pj_list_size(&pcv->other_param));

  // Test the icid-value has its quotes replaced after printing.
  char buf[1024];
  hdr = (pjsip_hdr*)pcv;
  int written = hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 140);
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"4815162542\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(CustomHeadersTest, PChargingFunctionAddresses)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Function-Addresses: ecf=10.0.0.1; ccf=10.0.0.2; ecf=10.0.0.3; ccf=10.0.0.4; other-param=test-value\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Charging-Function-Addresses");
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                          &header_name,
                                                          NULL);
  EXPECT_NE(hdr, (pjsip_hdr*)NULL);

  // We have a P-CFA header, check it was filled out correctly.
  pjsip_p_c_f_a_hdr* pcfa = (pjsip_p_c_f_a_hdr*)hdr;

  EXPECT_EQ(2u, pj_list_size(&pcfa->ccf));
  EXPECT_EQ(2u, pj_list_size(&pcfa->ecf));
  EXPECT_EQ(1u, pj_list_size(&pcfa->other_param));

  // Test the VPTR functions (clone, shallow clone and print on).
  pjsip_p_c_f_a_hdr* pcfa_clone = (pjsip_p_c_f_a_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(2u, pj_list_size(&pcfa_clone->ccf));
  EXPECT_EQ(2u, pj_list_size(&pcfa_clone->ecf));
  EXPECT_EQ(1u, pj_list_size(&pcfa_clone->other_param));

  pjsip_p_c_f_a_hdr* pcfa_sclone = (pjsip_p_c_f_a_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(2u, pj_list_size(&pcfa_sclone->ccf));
  EXPECT_EQ(2u, pj_list_size(&pcfa_sclone->ecf));
  EXPECT_EQ(1u, pj_list_size(&pcfa_sclone->other_param));

  char buf[1024];
  hdr = (pjsip_hdr*)pcfa_clone;
  int written = hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 105);
  EXPECT_STREQ("P-Charging-Function-Addresses: ccf=10.0.0.2;ccf=10.0.0.4;ecf=10.0.0.1;ecf=10.0.0.3;other-param=test-value", buf);
}

TEST_F(CustomHeadersTest, SessionExpires)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Session-Expires: 600;other-param=10;refresher=uas;more-param=42\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Session-Expires");
  pjsip_session_expires_hdr* hdr =
      (pjsip_session_expires_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                             &header_name,
                                                             NULL);
  EXPECT_NE(hdr, (pjsip_session_expires_hdr*)NULL);
  EXPECT_EQ(600, hdr->expires);
  EXPECT_EQ(SESSION_REFRESHER_UAS, hdr->refresher);
  EXPECT_EQ(2u, pj_list_size(&hdr->other_param));

  pjsip_session_expires_hdr* clone = (pjsip_session_expires_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);
  EXPECT_EQ(600, clone->expires);
  EXPECT_EQ(SESSION_REFRESHER_UAS, clone->refresher);
  EXPECT_EQ(2u, pj_list_size(&clone->other_param));

  pjsip_session_expires_hdr* sclone = (pjsip_session_expires_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);
  EXPECT_EQ(600, sclone->expires);
  EXPECT_EQ(SESSION_REFRESHER_UAS, sclone->refresher);
  EXPECT_EQ(2u, pj_list_size(&sclone->other_param));

  char buf[1024];
  pjsip_hdr* generic_hdr = (pjsip_hdr*)clone;
  int written = generic_hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 63);
  EXPECT_STREQ("Session-Expires: 600;refresher=uas;other-param=10;more-param=42", buf);
}
