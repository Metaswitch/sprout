/**
 * @file sproutletproxy.h  Sproutlet controller proxy class definition
 *
 * Project Clearwater - IMS in the Cloud
 * Copyright (C) 2014  Metaswitch Networks Ltd
 *
 * Parts of this module were derived from GPL licensed PJSIP sample code
 * with the following copyrights.
 *   Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 *   Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
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

#ifndef SPROUTLETPROXY_H__
#define SPROUTLETPROXY_H__

#include <map>
#include <unordered_map>
#include <list>

#include "basicproxy.h"
#include "sproutlet.h"

class SproutletProxy : public BasicProxy
{
public:
  /// Constructor.
  SproutletProxy(pjsip_endpoint* endpt,
                 int priority,
                 const std::string& uri,
                 const std::list<Sproutlet*>& sproutlets);

  /// Destructor.
  ~SproutletProxy();

protected:
  /// Create Sproutlet UAS transaction objects.
  BasicProxy::UASTsx* create_uas_tsx();

  std::list<Sproutlet*> target_sproutlets(pjsip_msg* msg);

  void add_record_route(pjsip_tx_data* tdata,
                        const std::string& service_name,
                        const std::string& dialog_id);

  class UASTsx : public BasicProxy::UASTsx
  {
    class TsxHelper;

  public:
    /// Constructor.
    UASTsx(BasicProxy* proxy);

    /// Destructor.
    ~UASTsx();

    /// Initializes the UAS transaction.
    virtual pj_status_t init(pjsip_rx_data* rdata);

    /// Handle the incoming half of a transaction request.
    virtual void process_tsx_request();

    /// Handle a received CANCEL request.
    virtual void process_cancel_request(pjsip_rx_data* rdata);

  protected:
    /// Handles a response to an associated UACTsx.
    virtual void on_new_client_response(UACTsx* uac_tsx,
                                        pjsip_tx_data *tdata);

    virtual void on_tsx_state(pjsip_event* event);

    virtual void add_record_route(pjsip_tx_data* tdata,
                                  const std::string& service_name,
                                  const std::string& dialog_id);

    virtual void tx_sproutlet_request(pjsip_tx_data* req,
                                      int fork_id,
                                      TsxHelper* helper);

    virtual void tx_sproutlet_response(pjsip_tx_data* rsp,
                                       TsxHelper* helper);

    virtual void tx_sproutlet_cancel(int status_code,
                                     int fork_id,
                                     TsxHelper* helper);

  private:
    class TsxHelper : public SproutletTsxHelper
    {
      typedef std::unordered_map<const pjsip_msg*, pjsip_tx_data*> Packets;
      typedef std::unordered_map<int, pjsip_tx_data*> Requests;
      typedef std::list<pjsip_tx_data*> Responses;

    public:
      /// Constructor
      TsxHelper(SproutletProxy::UASTsx* proxy_tsx,
                Sproutlet* sproutlet,
                pjsip_tx_data* req,
                SAS::TrailId trail_id);

      /// Virtual destructor.
      virtual ~TsxHelper();

      /// This implementation has concrete implementations for all of the virtual
      /// functions from SproutletTsxHelper.  See there for function comments for
      /// the following.
      void add_to_dialog(const std::string& dialog_id="");
      const std::string& dialog_id() const;
      pjsip_msg* clone_request(pjsip_msg* req);
      pjsip_msg* create_response(pjsip_msg* req,
                                 pjsip_status_code status_code,
                                 const std::string& status_text="");
      int send_request(pjsip_msg*& req);
      void send_response(pjsip_msg*& rsp); 
      void cancel_fork(int fork_id, int reason=0);
      void cancel_pending_forks(int reason=0);
      void free_msg(pjsip_msg*& msg);
      pj_pool_t* get_pool(const pjsip_msg* msg);
      bool schedule_timer(int id, void* context, int duration);
      void cancel_timer(int id);
      bool timer_running(int id);
      SAS::TrailId trail() const;

    private:

      void rx_request(pjsip_tx_data* req);
      void rx_response(pjsip_tx_data* rsp, int fork_id);
      void rx_cancel(pjsip_rx_data* cancel);
      void rx_error(int status_code);
      void register_tdata(pjsip_tx_data* tdata);

      void process_actions();
      void aggregate_response(pjsip_tx_data* rsp);
      void tx_request(pjsip_tx_data* req, int fork_id);
      void tx_response(pjsip_tx_data* rsp);
      int compare_sip_sc(int sc1, int sc2);

      SproutletProxy::UASTsx* _proxy_tsx;

      SproutletTsx* _sproutlet;

      std::string _service_name;

      pjsip_method_e _method;

      Packets _packets;

      Requests _send_requests;
      Responses _send_responses;

      std::string _dialog_id;
      bool _record_routed;

      int _pending_sends;
      int _pending_responses;
      pjsip_tx_data* _best_rsp;

      bool _complete;

      // Vector keeping track of the status of each fork.  The state field can
      // only ever take a subset of the values defined by PJSIP - NULL, CALLING,
      // PROCEEDING and COMPLETED.
      typedef struct
      {
        pjsip_tsx_state_e state;
        bool pending_cancel;
        int cancel_reason;
      } ForkStatus;
      std::vector<ForkStatus> _forks;

      SAS::TrailId _trail_id;

      friend class SproutletProxy::UASTsx;
    };

    /// Records whether or not the request is an in-dialog request.
    bool _in_dialog;

    /// Flags whether or not this node has already Record-Routed itself on
    /// this transaction.
    bool _record_routed;

    std::string _service_name;
    TsxHelper* _helper;
    SproutletTsx* _sproutlet;

    std::vector<int> _uac_2_fork;
    std::vector<int> _fork_2_uac;

    friend class TsxHelper;
  };

  pjsip_uri* _uri;

  std::map<std::string, Sproutlet*> _sproutlets;

  //friend class UASTsx::TsxHelper;
  friend class UASTsx;
};



#endif
