/**
 * @file fakesnmp.cpp Fake SNMP infrastructure (for testing).
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2015 Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version, along with the "Special Exception" for use of
 * the program along with SSL, set forth below. This program is distributed
 * in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details. You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by
 * post at Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 *
 * Special Exception
 * Metaswitch Networks Ltd  grants you permission to copy, modify,
 * propagate, and distribute a work formed by combining OpenSSL with The
 * Software, or a work derivative of such a combination, even if such
 * copying, modification, propagation, or distribution would otherwise
 * violate the terms of the GPL. You must comply with the GPL in all
 * respects for all of the code used other than OpenSSL.
 * "OpenSSL" means OpenSSL toolkit software distributed by the OpenSSL
 * Project and licensed under the OpenSSL Licenses, or a work based on such
 * software and licensed under the OpenSSL Licenses.
 * "OpenSSL Licenses" means the OpenSSL License and Original SSLeay License
 * under which the OpenSSL Project distributes the OpenSSL toolkit software,
 * as those licenses appear in the file LICENSE-OPENSSL.
 */

#include "snmp_includes.h"

// Stub out the net-snmp functions we call for UT.

int netsnmp_tdata_register(netsnmp_handler_registration *reginfo,
                           netsnmp_tdata *table,
                           netsnmp_table_registration_info *table_info)
{
  return 0;
}

int netsnmp_tdata_add_row(netsnmp_tdata *table, netsnmp_tdata_row *row)
{
  return 0;
}

netsnmp_tdata_row* netsnmp_tdata_remove_row(netsnmp_tdata *table,
                                            netsnmp_tdata_row *row)
{
  return row;
}

netsnmp_handler_registration* netsnmp_handler_registration_create(const char *name,
                                                                  netsnmp_mib_handler *handler,
                                                                  oid * reg_oid,
                                                                  size_t reg_oid_len,
                                                                  int modes)
{
  return NULL;
}

netsnmp_handler_registration* netsnmp_create_handler_registration(const char *name,
                                                                  Netsnmp_Node_Handler* handler_access_method,
                                                                  oid *reg_oid,
                                                                  size_t reg_oid_len,
                                                                  int modes)
{
  return NULL;
}

int netsnmp_unregister_handler(netsnmp_handler_registration *reginfo)
{
  return 0;
}

void snmp_free_varbind( netsnmp_variable_list *variables)
{
}

int netsnmp_register_read_only_ulong_instance(const char *name,
                                              oid *reg_oid,
                                              size_t reg_oid_len,
                                              u_long *it,
                                              Netsnmp_Node_Handler *subhandler)
{
  return 0; 
}

netsnmp_variable_list *snmp_varlist_add_variable(netsnmp_variable_list** varlist,
                                                 const oid * name,
                                                 size_t name_length,
                                                 u_char type,
                                                 const u_char * value,
                                                 size_t len)
{
  return NULL;
}
