

extern "C" {
#include <pjsip.h>
}


#include "log.h"
#include "appserver.h"

/// Sample AppServerTsx that forks the transaction.
class SampleForkASTsx : public AppServerTsx
{
public:
  SampleForkASTsx() :
    AppServerTsx() {}

  void on_initial_request(pjsip_msg* req)
  {
    TRC_DEBUG("SampleForkAS - process request %p", req);

    // Add the app to the dialog.
    add_to_dialog("fred");

    // Clone the request and redirect it to an external number
    pjsip_msg* clone = clone_request(req);

    if (PJSIP_URI_SCHEME_IS_SIP(clone->line.req.uri))
    {
      TRC_DEBUG("Forking request to external number");
      pjsip_sip_uri* sip_uri = (pjsip_sip_uri*)clone->line.req.uri;
      pj_strdup2(get_pool(clone), &sip_uri->user, "011442083627241");
      send_request(clone);
    }
    else
    {
      TRC_DEBUG("Not SIP URI, so don't fork");
      free_msg(clone);
    }

    TRC_DEBUG("Forwarding original request");
    send_request(req);
  }
};


class SampleForkAS : public AppServer
{
public:
  SampleForkAS() :
    AppServer("sample-fork")
  {
  }

  AppServerTsx* get_app_tsx(SproutletProxy* proxy, pjsip_msg* req, pjsip_sip_uri*& next_hop, pj_pool_t* pool, SAS::TrailId trail)
  {
    return (AppServerTsx*) new SampleForkASTsx();
  }
};


