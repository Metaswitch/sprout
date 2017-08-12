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
  process_aor_timeout(_aor_id);
}
