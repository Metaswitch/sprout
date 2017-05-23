/**
 * @file vped_sprout_types.h
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

// Typedefs for events & markers for VPED that we use in sprout

// Dummy event, used purely to have something show up in SAS. Expect to remove this
typedef struct dummy_event
{
  VPED_EVENT_HDR hdr;
  VPED_VAR_LEN_DATA ip_addr;

} DUMMY_EVENT;

// Struct for marker without any attached data. Used for start/end timestamp markers
typedef struct no_data_marker
{
  VPED_EVENT_HDR hdr;
} NO_DATA_MARKER;

// Struct used for calling/called DN markers
typedef struct dn_marker
{
  VPED_EVENT_HDR hdr;
  VPED_VAR_LEN_DATA dn;
} CALLING_DN_MARKER;
