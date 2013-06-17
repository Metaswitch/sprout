#include "log.h"
#include "logger.h"
#include "memcachedstorefactory.h"
#include "utils.h"
#include "stack.h"

static void log_bindings(const std::string& aor_name, RegData::AoR* aor_data)
{
  printf("Bindings for %s\n", aor_name.c_str());
  for (RegData::AoR::Bindings::const_iterator i = aor_data->bindings().begin();
       i != aor_data->bindings().end();
       ++i)
  {
    RegData::AoR::Binding* binding = i->second;
    printf("  %s: URI=%s expires=%d q=%d from %s cseq %d\n",
           i->first.c_str(),
           binding->_uri.c_str(),
           (int)(binding->_expires - time(NULL)),
           binding->_priority,
           binding->_cid.c_str(),
           binding->_cseq);
  }
}


int main (int argc, char *argv[])
{
  if (argc < 7)
  {
    printf("Usage: %s <store IP address list> <address of record> <binding identifier> <contact URI> <expires> <priority>\n", argv[0]);
    exit(1);
  }

  std::string servers(argv[1]);
  std::string aor(argv[2]);
  std::string binding_id(argv[3]);
  std::string contact_uri(argv[4]);
  int expires = atoi(argv[5]);
  int priority = atoi(argv[6]);

  Log::setLoggingLevel(2);
  Log::setLogger(new Logger());

  // Open the store.
  std::list<std::string> server_list;
  Utils::split_string(servers, ',', server_list, 0, true);
  RegData::Store* store = RegData::create_memcached_store(server_list, 100);

  RegData::AoR* aor_data = NULL;

  do
  {
    // Delete AoR data if we already been round once.
    delete aor_data;

    // Get the data for the AoR.
    aor_data = store->get_aor_data(aor);

    if (aor_data == NULL)
    {
      printf("Failed to get aor_data for %s\n", aor.c_str());
      exit(1);
    }

    // Find or add the specified binding.
    RegData::AoR::Binding* binding = aor_data->get_binding(binding_id);

    // Update the binding
    binding->_uri = contact_uri;
    binding->_priority = priority;
    binding->_expires = time(NULL) + expires;

  } while (!store->set_aor_data(aor, aor_data));

  // Print the data.
  log_bindings(aor, aor_data);

  delete aor_data;

  exit(0);
}
