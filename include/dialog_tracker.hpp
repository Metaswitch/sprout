/**
 * Copyright (C) Metaswitch Networks 2013
 * If license terms are provided to you in a COPYING file in the root directory
 * of the source code repository by which you are accessing this code, then
 * the license outlined in that COPYING file applies to your use.
 * Otherwise no rights are granted except for those provided to you by
 * Metaswitch Networks in a separate written agreement.
 */
extern "C" {
#include <pjsip.h>
#include <pjlib-util.h>
#include <pjlib.h>
#include <stdint.h>
}
#include "flowtable.h"

class DialogTracker {
  FlowTable* _ft;
public:
  DialogTracker(FlowTable* ft): _ft(ft) {};
  void on_uas_tsx_complete(const pjsip_tx_data* original_request,
                           const pjsip_transaction* tsx,
                           const pjsip_event* event,
                           bool is_client);
private:
  void on_dialog_start(const pjsip_tx_data* original_request,
                       const pjsip_transaction* tsx,
                       const pjsip_event* event,
                       bool is_client);

  void on_dialog_end(const pjsip_tx_data* original_request,
                     const pjsip_transaction* tsx,
                     const pjsip_event* event,
                     bool is_client);

  Flow* get_client_flow(const pjsip_tx_data* original_request,
                       const pjsip_transaction* tsx,
                       const pjsip_event* event,
                       bool is_client);
};
