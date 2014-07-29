#include "sproutletappserver.h"

// Before forwarding the request, reinsert any previously saved off Route: headers.
int SproutletAppServerTsxHelper::forward_request(pjsip_msg*& req)
{
  if (_fixed_route != NULL)
  {
    pjsip_hdr* cloned_hdr = (pjsip_hdr *)pjsip_hdr_clone(get_pool(req), 
                                                         _fixed_route);
    pjsip_msg_add_hdr(req, cloned_hdr);
  }
  return _helper->forward_request(req);
}

// Create the ServletTsx object for this transaction.  We do this by wrapping one
// from the AppServer itself.
SproutletTsx* SproutletAppServerShim::get_app_tsx(SproutletTsxHelper* helper,
                                                  pjsip_msg* req)
{
  SproutletTsx* tsx = NULL;

  // Create the helper for the AppServer layer.
  SproutletAppServerTsxHelper* shim_helper = new SproutletAppServerTsxHelper(helper);

  // Ask the AppServer for a Tsx.
  AppServerTsx* app_tsx = _app->get_app_tsx(shim_helper, req);
  if (app_tsx == NULL)
  {
    // Free up the shim_helper here, as we're bailing out.
    delete shim_helper; shim_helper = NULL;
  }
  else
  {
    tsx = new SproutletAppServerShimTsx(helper,
                                        shim_helper,
                                        app_tsx);
  }
  
  // The shim_helper has either been freed or taken by the ShimTsx
  assert(shim_helper == NULL);

  return tsx;
}

// Remove the top Route: header from the request and give it to the helper so
// it can be added back on later.
void SproutletAppServerShimTsx::on_initial_request(pjsip_msg* req)
{
  pjsip_hdr* hdr = (pjsip_hdr*)pjsip_msg_find_remove_hdr(req,
                                                         PJSIP_H_ROUTE,
                                                         NULL);
  _app_server_helper->set_fixed_route(hdr);
  _app_tsx->on_initial_request(req);
}
