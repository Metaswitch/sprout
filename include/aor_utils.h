/**
 * @file aor_utils.h Utility functions that sprout can call on an AoR. These are
 * not defined on the AoR itself, as they require access to PJSIP which is only
 * present in sprout.
 *
 * Copyright (C) Metaswitch Networks 2018
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

#ifndef AOR_UTILS_H__
#define AOR_UTILS_H__

extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
}

#include "aor.h"

namespace AoRUtils {

// Generates the public GRUU for this binding from the address of record and
// instance-id. Returns NULL if this binding has no valid GRUU.
pjsip_sip_uri* pub_gruu(const Binding* binding, pj_pool_t* pool);

// Utility method to return the public GRUU as a string.  Returns "" if this
// binding has no GRUU.
std::string pub_gruu_str(const Binding* binding, pj_pool_t* pool);

// Utility method to return the public GRUU surrounded by quotes.  Returns "" if
// this binding has no GRUU.
std::string pub_gruu_quoted_string(const Binding* binding, pj_pool_t* pool);

// Copies a Bindings object to return to the caller.
Bindings copy_bindings(Bindings bindings);

// Copies a Subscriptions object to return to the caller.
Subscriptions copy_subscriptions(Subscriptions subscriptions);

};

#endif

