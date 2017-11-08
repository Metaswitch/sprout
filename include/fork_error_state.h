/**
 * @file fork_error_state.h  Fork error state enum definition
 *
 * Copyright (C) Metaswitch Networks 2017
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef FORK_ERROR_STATE_H__
#define FORK_ERROR_STATE_H__

// If this enum is changed the corresponding "FORK_ERROR_TYPES" enum
// in the SAS resource bundle has to be updated too.
typedef enum {NONE, TIMEOUT, TRANSPORT_ERROR, NO_ADDRESSES} ForkErrorState;
const char* const FORK_ERROR_STATE_VALUES[] = {
  "NONE", "TIMER", "TRANSPORT_ERROR", "NO_ADDRESSES"};
inline const char* fork_error_to_str(const ForkErrorState fork_error)
  { return FORK_ERROR_STATE_VALUES[fork_error]; };

#endif
