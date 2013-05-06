/**
 * @file vped_sprout_types.h
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
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
