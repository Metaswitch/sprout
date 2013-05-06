/**
 * @file authentication.h Initialization and termination functions for Sprout Authentication module.
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

///
///

#ifndef AUTHENTICATION_H__
#define AUTHENTICATION_H__

extern pjsip_module mod_auth;

pj_status_t init_authentication(const std::string& realm_name,
                                bool tp_auth,
                                const std::string& auth_config,
                                HSSConnection* hss_connection,
                                AnalyticsLogger* analytics_logger);

void destroy_authentication();

#endif
