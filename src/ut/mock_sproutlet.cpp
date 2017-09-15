#include "mock_sproutlet.h"

MockSproutlet::MockSproutlet(
      const std::string& service_name="mock-sproutlet",
      int port=0,
      const std::string& service_host="") :
    Sproutlet(service_name, port, service_host) {}

MockSproutlet::~MockSproutlet() {}

MockSproutletTsx::MockSproutletTsx() :
    SproutletTsx(NULL)
{}

MockSproutletTsx::~MockSproutletTsx() {}


