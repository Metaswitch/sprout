/**
 * @file sip_parser_test.cpp UT for SIP parser testing. This checks custom
 * header parsing, and other specific parser functionality.
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include <string>
#include <gtest/gtest.h>

#include "siptest.hpp"
#include "pjutils.h"
#include "stack.h"
#include "custom_headers.h"

using namespace std;

#define EXPECT_PJEQ(X, Y) EXPECT_EQ(PJUtils::pj_str_to_string(&X), string(Y))

/// Fixture for SIP Parser testing
class SipParserTest : public SipTest
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

TEST_F(SipParserTest, PChargingVector)
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

TEST_F(SipParserTest, PChargingVectorQuotedIcidValue)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=\"a2bb639b437cd5827a8f54fe39f3987c0:0:0:0:0:0:0:0\"; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
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

  EXPECT_PJEQ(pcv->icid, "a2bb639b437cd5827a8f54fe39f3987c0:0:0:0:0:0:0:0");
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
  EXPECT_EQ(written, 177);
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"a2bb639b437cd5827a8f54fe39f3987c0:0:0:0:0:0:0:0\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(SipParserTest, PChargingVectorHostnameIcidValue)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=subdomain.example.com; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
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

  EXPECT_PJEQ(pcv->icid, "subdomain.example.com");
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
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"subdomain.example.com\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(SipParserTest, PChargingVectorIPv6IcidValue)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=[::1]; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
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

  EXPECT_PJEQ(pcv->icid, "[::1]");
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
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"[::1]\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(SipParserTest, PChargingVectorEmptyIcidValue)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Vector: icid-value=""; orig-ioi=homedomain; term-ioi=remotedomain; icid-generated-at=edge.proxy.net; other-param=test-value\n"
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

  EXPECT_PJEQ(pcv->icid, "");
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
  EXPECT_STREQ("P-Charging-Vector: icid-value=\"\";orig-ioi=homedomain;term-ioi=remotedomain;icid-generated-at=edge.proxy.net;other-param=test-value", buf);
}

TEST_F(SipParserTest, PChargingFunctionAddresses)
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

TEST_F(SipParserTest, PChargingFunctionAddressesIPv6)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Function-Addresses: ccf=10.22.42.18;ccf=[FD5F:5D21:845:1C27:FF00::42:105]\n"
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
  EXPECT_EQ(0u, pj_list_size(&pcfa->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa->other_param));

  // Test the VPTR functions (clone, shallow clone and print on).
  pjsip_p_c_f_a_hdr* pcfa_clone = (pjsip_p_c_f_a_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(2u, pj_list_size(&pcfa_clone->ccf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_clone->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_clone->other_param));

  pjsip_p_c_f_a_hdr* pcfa_sclone = (pjsip_p_c_f_a_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(2u, pj_list_size(&pcfa_sclone->ccf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_sclone->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_sclone->other_param));

  char buf[1024];
  hdr = (pjsip_hdr*)pcfa_clone;
  int written = hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 84);
  EXPECT_STREQ("P-Charging-Function-Addresses: ccf=10.22.42.18;ccf=[FD5F:5D21:845:1C27:FF00::42:105]", buf);
}

TEST_F(SipParserTest, PChargingFunctionAddressesOneIPv6)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtKqxhkZnvVKI2LUEWoZVFjFaqo.cOzf;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "P-Charging-Function-Addresses: ccf=[fd5f:5d21:845:1c27:ff00:0:42:105]\n"
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

  EXPECT_EQ(1u, pj_list_size(&pcfa->ccf));
  EXPECT_EQ(0u, pj_list_size(&pcfa->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa->other_param));

  // Test the VPTR functions (clone, shallow clone and print on).
  pjsip_p_c_f_a_hdr* pcfa_clone = (pjsip_p_c_f_a_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(1u, pj_list_size(&pcfa_clone->ccf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_clone->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_clone->other_param));

  pjsip_p_c_f_a_hdr* pcfa_sclone = (pjsip_p_c_f_a_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);

  EXPECT_EQ(1u, pj_list_size(&pcfa_sclone->ccf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_sclone->ecf));
  EXPECT_EQ(0u, pj_list_size(&pcfa_sclone->other_param));

  char buf[1024];
  hdr = (pjsip_hdr*)pcfa_clone;
  int written = hdr->vptr->print_on(hdr, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = hdr->vptr->print_on(hdr, buf, i);
    i++;
  }
  EXPECT_EQ(written, 69);
  EXPECT_STREQ("P-Charging-Function-Addresses: ccf=[fd5f:5d21:845:1c27:ff00:0:42:105]", buf);
}


TEST_F(SipParserTest, SessionExpires)
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

TEST_F(SipParserTest, SessionExpiresUAC)
{
  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Session-Expires: 600;other-param=10;refresher=uac;more-param=42\n"
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
  EXPECT_EQ(SESSION_REFRESHER_UAC, hdr->refresher);
  EXPECT_EQ(2u, pj_list_size(&hdr->other_param));

  pjsip_session_expires_hdr* clone = (pjsip_session_expires_hdr*)hdr->vptr->clone(stack_data.pool, (void*)hdr);
  EXPECT_EQ(600, clone->expires);
  EXPECT_EQ(SESSION_REFRESHER_UAC, clone->refresher);
  EXPECT_EQ(2u, pj_list_size(&clone->other_param));

  pjsip_session_expires_hdr* sclone = (pjsip_session_expires_hdr*)hdr->vptr->shallow_clone(stack_data.pool, (void*)hdr);
  EXPECT_EQ(600, sclone->expires);
  EXPECT_EQ(SESSION_REFRESHER_UAC, sclone->refresher);
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
  EXPECT_STREQ("Session-Expires: 600;refresher=uac;other-param=10;more-param=42", buf);
}

TEST_F(SipParserTest, AcceptContact)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Accept-Contact: *;+sip.instance=\"<i:am:a:robot>\";explicit;require\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Accept-Contact");
  pjsip_accept_contact_hdr* hdr =
      (pjsip_accept_contact_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                            NULL);
  EXPECT_NE(hdr, (pjsip_accept_contact_hdr*)NULL);
  EXPECT_EQ(true, hdr->required_match);
  EXPECT_EQ(true, hdr->explicit_match);
  EXPECT_EQ(1u, pj_list_size(&hdr->feature_set));

  pjsip_accept_contact_hdr* clone = (pjsip_accept_contact_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);
  EXPECT_EQ(true, clone->required_match);
  EXPECT_EQ(true, clone->explicit_match);
  EXPECT_EQ(1u, pj_list_size(&clone->feature_set));

  pjsip_accept_contact_hdr* sclone = (pjsip_accept_contact_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);
  EXPECT_EQ(true, sclone->required_match);
  EXPECT_EQ(true, sclone->explicit_match);
  EXPECT_EQ(1u, pj_list_size(&sclone->feature_set));

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_EQ(written, 65);
  EXPECT_STREQ("Accept-Contact: *;+sip.instance=\"<i:am:a:robot>\";explicit;require", buf);
  pj_pool_release(clone_pool);

  // Repeat parse check with a minimal Accept-Contact header
  string str2("INVITE sip:6505554321@homedomain SIP/2.0\n"
              "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
              "Max-Forwards: 63\n"
              "From: <sip:6505551234@homedomain>;tag=1234\n"
              "To: <sip:6505554321@homedomain>\n"
              "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
              "Call-ID: 1-13919@10.151.20.48\n"
              "CSeq: 1 INVITE\n"
              "Accept-Contact: *\n"
              "Content-Length: 0\n\n");

  rdata = build_rxdata(str2, _tp_default, main_pool);
  parse_rxdata(rdata);
  hdr =
      (pjsip_accept_contact_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                            NULL);
  EXPECT_NE(hdr, (pjsip_accept_contact_hdr*)NULL);
  EXPECT_NE(true, hdr->required_match);
  EXPECT_NE(true, hdr->explicit_match);
  EXPECT_EQ(0u, pj_list_size(&hdr->feature_set));

  pj_pool_release(main_pool);
}

TEST_F(SipParserTest, RejectContact)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Reject-Contact: *;+sip.instance=\"<i:am:a:robot>\"\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Reject-Contact");
  pjsip_reject_contact_hdr* hdr =
      (pjsip_reject_contact_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                            NULL);
  EXPECT_NE(hdr, (pjsip_reject_contact_hdr*)NULL);
  EXPECT_EQ(1u, pj_list_size(&hdr->feature_set));

  pjsip_reject_contact_hdr* clone = (pjsip_reject_contact_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);
  EXPECT_EQ(1u, pj_list_size(&clone->feature_set));

  pjsip_reject_contact_hdr* sclone = (pjsip_reject_contact_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);
  EXPECT_EQ(1u, pj_list_size(&sclone->feature_set));

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("Reject-Contact: *;+sip.instance=\"<i:am:a:robot>\"", buf);
  pj_pool_release(clone_pool);
}

TEST_F(SipParserTest, PAssociatedURI)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "P-Associated-URI: <sip:uri1@example.com;uriparam>;aiparam,<sip:uri2@example.com;uriparam2>;aiparam2\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Associated-URI");
  pjsip_route_hdr* hdr =
      (pjsip_route_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                            NULL);
  EXPECT_NE(hdr, (pjsip_route_hdr*)NULL);

  pjsip_route_hdr* clone = (pjsip_route_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);

  pjsip_route_hdr* sclone = (pjsip_route_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);

  pjsip_route_hdr* hdr2 =
      (pjsip_route_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                   (hdr->next));
  EXPECT_NE(hdr2, (pjsip_route_hdr*)NULL);

  pjsip_route_hdr* clone2 = (pjsip_route_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr2);

  pjsip_route_hdr* sclone2 = (pjsip_route_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone2);

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("P-Associated-URI: <sip:uri1@example.com;uriparam>;aiparam", buf);

  memset(buf, 0, 1024);
  written = generic_hdr->vptr->print_on(sclone2, buf, 0);
  EXPECT_EQ(written, -1);
  i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone2, buf, i);
    i++;
  }
  EXPECT_STREQ("P-Associated-URI: <sip:uri2@example.com;uriparam2>;aiparam2", buf);
  pj_pool_release(clone_pool);
}

TEST_F(SipParserTest, PAssertedIdentity)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "P-Asserted-Identity: <sip:uri1@example.com>,<sip:uri2@example.com>\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Asserted-Identity");
  pjsip_route_hdr* hdr =
      (pjsip_route_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                            NULL);
  pjsip_route_hdr* hdr2 =
      (pjsip_route_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                            &header_name,
                                                   (hdr->next));
  EXPECT_NE(hdr, (pjsip_route_hdr*)NULL);

  pjsip_route_hdr* clone = (pjsip_route_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);

  pjsip_route_hdr* sclone = (pjsip_route_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);

  EXPECT_NE(hdr2, (pjsip_route_hdr*)NULL);

  pjsip_route_hdr* clone2 = (pjsip_route_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr2);

  pjsip_route_hdr* sclone2 = (pjsip_route_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone2);

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("P-Asserted-Identity: <sip:uri1@example.com>", buf);

  memset(buf, 0, 1024);
  written = generic_hdr->vptr->print_on(sclone2, buf, 0);
  EXPECT_EQ(written, -1);
  i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone2, buf, i);
    i++;
  }
  EXPECT_STREQ("P-Asserted-Identity: <sip:uri2@example.com>", buf);
  pj_pool_release(clone_pool);
}

// Test that you can create a P-Profile-Key header, parse it and clone it
// without any issues
TEST_F(SipParserTest, PProfileKey)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "P-Profile-Key: <sip:uri!%5b0-9%5d%7b2%7d.*!!!@example.com>;test-param;test-param2=value\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("P-Profile-Key");
  pjsip_route_hdr* hdr =
      (pjsip_route_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                   &header_name,
                                                   NULL);
  EXPECT_NE(hdr, (pjsip_route_hdr*)NULL);
  pjsip_route_hdr* clone = (pjsip_route_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);
  pjsip_route_hdr* sclone = (pjsip_route_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);
  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);

  int i = 1;
  while ((written == -1) && (i <= 1024))
  {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("P-Profile-Key: <sip:uri!%5b0-9%5d%7b2%7d.*!!!@example.com>;test-param;test-param2=value", buf);

  pj_pool_release(clone_pool);
}

TEST_F(SipParserTest, ServiceRoute)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Service-Route: <sip:sprout.example.com:5054;transport=TCP;lr;orig>;x=2;y=3, <sip:sprout2.example.com:5054;lr;orig>;z=2x+y\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Service-Route");
  pjsip_routing_hdr* hdr =
      (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                     &header_name,
                                                     NULL);
  EXPECT_NE(hdr, (pjsip_routing_hdr*)NULL);

  pjsip_routing_hdr* hdr2 =
      (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                     &header_name,
                                                     hdr->next);
  EXPECT_NE(hdr2, (pjsip_routing_hdr*)NULL);

  pjsip_routing_hdr* clone = (pjsip_routing_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);

  pjsip_routing_hdr* sclone = (pjsip_routing_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("Service-Route: <sip:sprout.example.com:5054;transport=TCP;lr;orig>;x=2;y=3", buf);
}

TEST_F(SipParserTest, Path)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("REGISTER sip:homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Path: <sip:12345678@example.com:5054;transport=TCP;lr>;x=2;y=3, <sip:sprout.example.com:5054;lr>;z=2x+y\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Path");
  pjsip_routing_hdr* hdr =
      (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                     &header_name,
                                                     NULL);
  EXPECT_NE(hdr, (pjsip_routing_hdr*)NULL);

  pjsip_routing_hdr* hdr2 =
      (pjsip_routing_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                     &header_name,
                                                     hdr->next);
  EXPECT_NE(hdr2, (pjsip_routing_hdr*)NULL);

  pjsip_routing_hdr* clone = (pjsip_routing_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);

  pjsip_routing_hdr* sclone = (pjsip_routing_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("Path: <sip:12345678@example.com:5054;transport=TCP;lr>;x=2;y=3", buf);
}

TEST_F(SipParserTest, MinSE)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Min-SE: 300;other-param=other-param-value\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Min-SE");
  pjsip_min_se_hdr* hdr =
      (pjsip_min_se_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                    &header_name,
                                                    NULL);
  EXPECT_NE(hdr, (pjsip_min_se_hdr*)NULL);

  pjsip_min_se_hdr* clone = (pjsip_min_se_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);

  pjsip_min_se_hdr* sclone = (pjsip_min_se_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);
  int i = 1;
  while ((written == -1) && (i <= 1024)) {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("Min-SE: 300;other-param=other-param-value", buf);
}

TEST_F(SipParserTest, StarHashToHeader)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:*1234#@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "CSeq: 1 INVITE\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("To");
  pjsip_to_hdr* hdr =
      (pjsip_to_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                &header_name,
                                                NULL);
  EXPECT_NE(hdr, (pjsip_to_hdr*)NULL);
  pjsip_name_addr* uri = (pjsip_name_addr*) hdr->uri;
  pjsip_sip_uri* sip_uri = (pjsip_sip_uri*) uri->uri;
  pj_str_t* user = &(sip_uri->user);
  pj_str_t goal = pj_str("*1234#");
  EXPECT_EQ(pj_strcmp(user, &goal), 0);
}

// Test that you can create a Resource-Priority header, parse it and clone it
// without any issues
TEST_F(SipParserTest, ResourcePriority)
{
  pj_pool_t *main_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                 PJSIP_POOL_RDATA_LEN,
                                                 PJSIP_POOL_RDATA_INC);
  pj_pool_t *clone_pool = pjsip_endpt_create_pool(stack_data.endpt, "rtd%p",
                                                  PJSIP_POOL_RDATA_LEN,
                                                  PJSIP_POOL_RDATA_INC);

  string str("INVITE sip:6505554321@homedomain SIP/2.0\n"
             "Via: SIP/2.0/TCP 10.0.0.1:5060;rport;branch=z9hG4bKPjPtVFjqo;alias\n"
             "Max-Forwards: 63\n"
             "From: <sip:6505551234@homedomain>;tag=1234\n"
             "To: <sip:6505554321@homedomain>\n"
             "Contact: <sip:6505551234@10.0.0.1:5060;transport=TCP;ob>\n"
             "Call-ID: 1-13919@10.151.20.48\n"
             "Resource-Priority: dsn.flash, wps.4\n"
             "CSeq: 1 INVITE\n"
             "Content-Length: 0\n\n");

  pjsip_rx_data* rdata = build_rxdata(str, _tp_default, main_pool);
  parse_rxdata(rdata);

  pj_str_t header_name = pj_str("Resource-Priority");
  pjsip_generic_array_hdr* hdr =
      (pjsip_generic_array_hdr*)pjsip_msg_find_hdr_by_name(rdata->msg_info.msg,
                                                               &header_name,
                                                               NULL);
  EXPECT_NE(hdr, (pjsip_generic_array_hdr*)NULL);
  EXPECT_EQ(hdr->count, 2);
  EXPECT_PJEQ(hdr->values[0], "dsn.flash");
  EXPECT_PJEQ(hdr->values[1], "wps.4");

  pjsip_generic_array_hdr* clone = (pjsip_generic_array_hdr*)hdr->vptr->clone(clone_pool, (void*)hdr);
  EXPECT_EQ(clone->count, 2);
  EXPECT_PJEQ(clone->values[0], "dsn.flash");
  EXPECT_PJEQ(clone->values[1], "wps.4");

  pjsip_generic_array_hdr* sclone = (pjsip_generic_array_hdr*)hdr->vptr->shallow_clone(clone_pool, (void*)clone);
  EXPECT_EQ(sclone->count, 2);
  EXPECT_PJEQ(sclone->values[0], "dsn.flash");
  EXPECT_PJEQ(sclone->values[1], "wps.4");

  pj_pool_release(main_pool);

  char buf[1024];
  memset(buf, 0, 1024);
  pjsip_hdr* generic_hdr = (pjsip_hdr*)sclone;
  int written = generic_hdr->vptr->print_on(sclone, buf, 0);
  EXPECT_EQ(written, -1);

  int i = 1;
  while ((written == -1) && (i <= 1024))
  {
    written = generic_hdr->vptr->print_on(sclone, buf, i);
    i++;
  }
  EXPECT_STREQ("Resource-Priority: dsn.flash, wps.4", buf);

  pj_pool_release(clone_pool);
}
