/**
 * @file chronoshandlers.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef CHRONOSHANDLERS_H__
#define CHRONOSHANDLERS_H__

#include "handlers.h"

class ChronosAoRTimeoutTaskHandler;

class ChronosAoRTimeoutTask : public AoRTimeoutTask
{
public:
  ChronosAoRTimeoutTask(HttpStack::Request& req,
                        const Config* cfg,
                        SAS::TrailId trail) :
    AoRTimeoutTask::AoRTimeoutTask(req, cfg, trail)
  {};

  void run();

protected:
  HTTPCode parse_response(std::string body);
  void handle_response();
  std::string _aor_id;

  friend class ChronosAoRTimeoutTaskHandler;
};

class ChronosAuthTimeoutTask : public AuthTimeoutTask
{
public:
  ChronosAuthTimeoutTask(HttpStack::Request& req,
                         const Config* cfg,
                         SAS::TrailId trail) :
    AuthTimeoutTask::AuthTimeoutTask(req, cfg, trail)
  {};

  void run();

protected:
  HTTPCode handle_response(std::string body);
};


#endif
