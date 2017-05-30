/**
 * @file options.h Initialization and termination functions for Sprout OPTIONS module.
 *
 * Copyright (C) Metaswitch Networks 2013
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */

///
///

#ifndef OPTIONS_H__
#define OPTIONS_H__

extern pjsip_module mod_options;

pj_status_t init_options();

void destroy_options();

#endif
