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

RegData::Store* store;

void write_store(const std::string& aor,
                 const std::string& binding_id,
                 const std::string& contact_uri,
                 int expires,
                 int priority)
{
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
  //log_bindings(aor, aor_data);

  delete aor_data;
}

int main (int argc, char *argv[])
{
  if (argc < 7)
  {
    printf("Usage: %s <store IP address list> <number of records> <address of record> <binding identifier> <contact URI> <expires> <priority>\n", argv[0]);
    exit(1);
  }

  std::string servers(argv[1]);
  int records = atoi(argv[2]);
  std::string aor_root(argv[3]);
  std::string binding_id(argv[4]);
  std::string contact_uri(argv[5]);
  int expires = atoi(argv[6]);
  int priority = atoi(argv[7]);

  Log::setLoggingLevel(2);
  Log::setLogger(new Logger());

  // Open the store.
  std::list<std::string> server_list;
  Utils::split_string(servers, ',', server_list, 0, true);
  store = RegData::create_memcached_store(server_list, 100);

  for (int ii = 0; ii < records; ++ii)
  {
    char index[10];
    sprintf(index, "%8.8d", ii);
    std::string aor = aor_root + std::string(index);
    write_store(aor, binding_id, contact_uri, expires, priority);
  }

  exit(0);
}
