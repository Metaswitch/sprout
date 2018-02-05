/**
 * @file registration_sender.h
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef REGISTRATION_SENDER_H__
#define REGISTRATION_SENDER_H__

#include "ifc.h"
#include "fifcservice.h"

class RegistrationSender
{
public:
  RegistrationSender(IFCConfiguration ifc_configuration,
                     FIFCService* fifc_service);

  virtual ~RegistrationSender();

  void register_with_application_servers();

  void deregister_with_application_servers();
};

#endif
