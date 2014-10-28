/**
 * @file simservs.h Interface declaration for the simservs XML parser
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

///
///

#ifndef SIMSERVS_H__
#define SIMSERVS_H__

#include <string>
#include <vector>

#include "rapidxml/rapidxml.hpp"

class simservs
{
public:
  simservs(std::string xml);
  simservs(const std::string forward_target,
           unsigned int conditions,
           unsigned int no_reply_timer);
  ~simservs();

  class Rule
  {
  public:
    Rule(rapidxml::xml_node<>* rule);
    Rule(unsigned int conditions) : _conditions(conditions) {};
    ~Rule();

    static const unsigned int CONDITION_BUSY =               0x0001;
    static const unsigned int CONDITION_NOT_REGISTERED =     0x0002;
    static const unsigned int CONDITION_NO_ANSWER =          0x0004;
    static const unsigned int CONDITION_NOT_REACHABLE =      0x0008;
    static const unsigned int CONDITION_MEDIA_AUDIO =        0x0010;
    static const unsigned int CONDITION_MEDIA_VIDEO =        0x0020;
    static const unsigned int CONDITION_ROAMING =            0x0040;
    static const unsigned int CONDITION_INTERNATIONAL =      0x0080;
    static const unsigned int CONDITION_INTERNATIONAL_EXHC = 0x0100;
    unsigned int conditions() const;

  private:
    unsigned int _conditions;
  };

  class CDIVRule : public Rule
  {
  public:
    CDIVRule(rapidxml::xml_node<>* rule);
    CDIVRule(const std::string forward_target, unsigned int conditions) :
      Rule(conditions), _forward_target(forward_target) {};
    ~CDIVRule();
    std::string forward_target() const;

  private:
    std::string _forward_target;
  };

  class CBRule : public Rule
  {
  public:
    CBRule(rapidxml::xml_node<>* rule);
    ~CBRule();
    bool allow_call() const;

  private:
    bool _allow_call;
  };

  bool oip_enabled();
  bool oir_enabled();
  bool oir_presentation_restricted();
  bool cdiv_enabled() const;
  unsigned int cdiv_no_reply_timer() const;
  const std::vector<CDIVRule>* cdiv_rules() const;
  bool inbound_cb_enabled() const;
  bool outbound_cb_enabled() const;
  const std::vector<CBRule>* inbound_cb_rules() const;
  const std::vector<CBRule>* outbound_cb_rules() const;

private:
  bool check_active(rapidxml::xml_node<> *service);

  bool _oip_enabled;

  bool _oir_enabled;
  bool _oir_presentation_restricted;

  bool _cdiv_enabled;
  unsigned int _cdiv_no_reply_timer;
  std::vector<CDIVRule> _cdiv_rules;

  bool _inbound_cb_enabled;
  bool _outbound_cb_enabled;
  std::vector<CBRule> _inbound_cb_rules;
  std::vector<CBRule> _outbound_cb_rules;
};

#endif
