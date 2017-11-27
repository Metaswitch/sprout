/**
 * @file chronoshandlers.cpp
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "json_parse_utils.h"

#include "chronoshandlers.h"
#include "log.h"
#include "pjutils.h"

class ChronosAoRTimeoutTaskHandler : public PJUtils::Callback
{
private:
  ChronosAoRTimeoutTask* _task;

public:
  ChronosAoRTimeoutTaskHandler(ChronosAoRTimeoutTask* task) :
    _task(task)
  {
  }

  virtual void run()
  {
    _task->handle_response();

    delete _task;
  }
};

void ChronosAoRTimeoutTask::run()
{
  if (_req.method() != htp_method_POST)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  HTTPCode rc = parse_response(_req.get_rx_body());

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Unable to parse response from Chronos");
    send_http_reply(rc);
    delete this;
    return;
  }

  send_http_reply(HTTP_OK);

  PJUtils::run_callback_on_worker_thread(new ChronosAoRTimeoutTaskHandler(this), false);
}

HTTPCode ChronosAoRTimeoutTask::parse_response(std::string body)
{
  rapidjson::Document doc;
  std::string json_str = body;
  doc.Parse<0>(json_str.c_str());

  if (doc.HasParseError())
  {
    TRC_DEBUG("Failed to parse opaque data as JSON: %s\nError: %s",
              json_str.c_str(),
              rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "aor_id", _aor_id);
  }
  catch (JsonFormatError err)
  {
    TRC_DEBUG("Badly formed opaque data (missing aor_id)");
    return HTTP_BAD_REQUEST;
  }


  return HTTP_OK;
}

void ChronosAoRTimeoutTask::handle_response()
{
  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  process_aor_timeout(_aor_id);

  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);
}

void ChronosAuthTimeoutTask::run()
{
  if (_req.method() != htp_method_POST)
  {
    send_http_reply(HTTP_BADMETHOD);
    delete this;
    return;
  }

  SAS::Marker start_marker(trail(), MARKER_ID_START, 1u);
  SAS::report_marker(start_marker);

  HTTPCode rc = handle_response(_req.get_rx_body());

  SAS::Marker end_marker(trail(), MARKER_ID_END, 1u);
  SAS::report_marker(end_marker);

  if (rc != HTTP_OK)
  {
    TRC_DEBUG("Unable to handle callback from Chronos");
    send_http_reply(rc);
    delete this;
    return;
  }

  send_http_reply(HTTP_OK);
  delete this;
}

HTTPCode ChronosAuthTimeoutTask::handle_response(std::string body)
{
  rapidjson::Document doc;
  std::string json_str = body;
  doc.Parse<0>(json_str.c_str());
  std::string impi;
  std::string impu;
  std::string nonce;

  if (doc.HasParseError())
  {
    TRC_INFO("Failed to parse opaque data as JSON: %s\nError: %s",
             json_str.c_str(),
             rapidjson::GetParseError_En(doc.GetParseError()));
    return HTTP_BAD_REQUEST;
  }

  try
  {
    JSON_GET_STRING_MEMBER(doc, "impu", impu);
    JSON_GET_STRING_MEMBER(doc, "impi", impi);
    JSON_GET_STRING_MEMBER(doc, "nonce", nonce);
  }
  catch (JsonFormatError err)
  {
    TRC_INFO("Badly formed opaque data (missing impu, impi or nonce");
    return HTTP_BAD_REQUEST;
  }
  return timeout_auth_challenge(impu, impi, nonce);
}
