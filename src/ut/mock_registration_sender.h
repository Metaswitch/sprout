/**
 * @file mock_registration_sender.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef MOCK_REGISTRATION_SENDER_H_
#define MOCK_REGISTRATION_SENDER_H_

#include "gmock/gmock.h"
#include "registration_sender.h"

class MockRegistrationSender : public RegistrationSender
{
public:
  MockRegistrationSender() :
    RegistrationSender({}, NULL) {};

  virtual ~MockRegistrationSender() {};
};

#endif
