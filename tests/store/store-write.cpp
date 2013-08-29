#include <getopt.h>
#include <sys/time.h>
#include <vector>
#include <string>
#include <sstream>

#include "log.h"
#include "logger.h"
#include "memcachedstorefactory.h"
#include "utils.h"
#include "stack.h"

// Options variables - all are read-only once the threads are started.
bool verbose = false;
std::string servers = "127.0.0.1:11211";
int num_threads = 1;
int num_records = 1;
int num_bindings = 1;
int expires = 300;
std::string protocol = "memcached-ascii";
int log_level = 2;
std::string aor_domain;

// Pointer to the store object - read-only once the threads are started.
RegData::Store* store;

template <class T>
std::string to_string(T t,                                 ///< datum to convert
                      std::ios_base & (*f)(std::ios_base&) ///< modifier to apply
                     )
{
  std::ostringstream oss;
  oss << f << t;
  return oss.str();
}

static void log_bindings(long tid, const std::string& aor_name, RegData::AoR* aor_data)
{
  printf("%ld: Bindings for %s\n", tid, aor_name.c_str());
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

static void* writer_thread(void* p)
{
  // Get the thread identifier from the parameter.  This ensures the AoRs
  // from different threads are different but predictable.
  long tid = (long)p;

  std::string aor_base = "aor" + to_string<int>(tid, std::dec);

  for (int ii = 0; ii < num_records; ++ii)
  {
    std::string aor_name = aor_base + "-" + to_string<long>(ii, std::dec) + "@" + aor_domain;

    RegData::AoR* aor_data = NULL;

    do
    {
      // Delete AoR data if we've already been round once.
      delete aor_data;

      // Get the data for the AoR.
      aor_data = store->get_aor_data(aor_name);

      if (aor_data == NULL)
      {
        printf("%ld: Failed to get aor_data for %s\n", tid, aor_name.c_str());
        exit(1);
      }

      for (int jj = 0; jj < num_bindings; ++jj)
      {
        // Find or add the specified binding.
        std::string binding_id = "binding" + to_string<int>(jj, std::dec);
        RegData::AoR::Binding* binding = aor_data->get_binding(binding_id);

        // Update the binding
        binding->_uri = binding_id + "@127.0.0.1;transport=TCP";
        binding->_priority = 1;
        binding->_expires = time(NULL) + expires;
      }

    } while (!store->set_aor_data(aor_name, aor_data));

    if (verbose)
    {
      // Print the data.
      log_bindings(tid, aor_name, aor_data);
    }

    delete aor_data;
  }

  return NULL;
}

static void usage(char* command)
{
  printf("%s [options] <address of record domain>\n", command);
  printf("Options:\n\n"
         " -v, --verbose                  Verbose\n"
         " -s, --servers <server list>    Specifies a comma separated list of servers in IP address:port\n"
         "                                format (default is 127.0.0.1:11211)\n"
         " -t, --threads <threads>        Specifies the number of threads to run (default is 1)\n"
         " -r, --records <records>        Specifies the number of records to write per thread (default\n"
         "                                is 1)\n"
         " -b, --bindings <bindings>      Specifies the number of bindings to write per record (default\n"
         "                                is 1)\n"
         " -e, --expires <expires>        Specifies the expires value for each record (default is 300)\n"
         " -p, --protocol <protocol>      Specifies protocol to use (memcached-ascii, memcached-binary,\n"
         "                                default is memcached-ascii)\n"
         " -L, --log-level <log-level>    Specifies the log level (default is 2)\n");
}

int main (int argc, char *argv[])
{
  // Parse the command line options
  while (true)
  {
    static struct option long_options[] =
    {
      {"verbose",             no_argument,               0, 'v'},
      {"servers",             required_argument,         0, 's'},
      {"threads",             required_argument,         0, 't'},
      {"records",             required_argument,         0, 'r'},
      {"bindings",            required_argument,         0, 'b'},
      {"expires",             required_argument,         0, 'e'},
      {"protocol",            required_argument,         0, 'p'},
      {"log-level",           required_argument,         0, 'L'},
      {0, 0, 0, 0}
    };


    // getopt_long stores the option index here.
    int option_index = 0;

    char c = getopt_long(argc, argv, "vs:t:r:b:e:p:L:", long_options, &option_index);

    // Detect the end of the options.
    if (c == -1)
    {
      break;
    }

    switch (c)
    {
      case 'v':
        verbose = true;
        break;

      case 's':
        servers = std::string(optarg);
        break;

      case 't':
        num_threads = atoi(optarg);
        break;

      case 'r':
        num_records = atoi(optarg);
        break;

      case 'b':
        num_bindings = atoi(optarg);
        break;

      case 'e':
        expires = atoi(optarg);
        break;

      case 'p':
        protocol = std::string(optarg);
        if ((protocol != "memcached-ascii") &&
            (protocol != "memcached-binary"))
        {
          printf("Unknown protocol %s\n", protocol.c_str());
          usage(argv[0]);
          exit(1);
        }
        break;

      case 'L':
        log_level = atoi(optarg);
        break;

      default:
        usage(argv[0]);
        exit(1);
    }
  }

  if (optind >= argc)
  {
    usage(argv[0]);
    exit(1);
  }

  // Get the AoR string.
  aor_domain = std::string(argv[optind]);

  printf("Servers = %s\n", servers.c_str());
  printf("%d threads writing %d records each\n", num_threads, num_records);
  printf("%d bindings per record\n", num_bindings);
  printf("AOR domain = %s\n", aor_domain.c_str());
  printf("Expires = %d\n", expires);
  printf("Protocol = %s\n", protocol.c_str());

  Log::setLoggingLevel(log_level);
  Log::setLogger(new Logger());

  // Open the store.
  std::list<std::string> server_list;
  Utils::split_string(servers, ',', server_list, 0, true);
  store = RegData::create_memcached_store(server_list, num_threads, (protocol == "memcached-binary"));

  std::vector<pthread_t> threads;

  struct timeval td;
  gettimeofday(&td, NULL);
  int64_t start_ms = td.tv_sec;
  start_ms = start_ms * 1000;
  int64_t usec = td.tv_usec;
  usec = usec / 1000;
  start_ms += usec;

  // Create the threads.
  for (int ii = 0; ii < num_threads; ++ii)
  {
    pthread_t tid;
    pthread_create(&tid, NULL, &writer_thread, (void*)(long)ii);
    threads.push_back(tid);
  }

  // Wait for the threads to exit.
  for (int ii = 0; ii < num_threads; ++ii)
  {
    pthread_join(threads[ii], NULL);
  }

  gettimeofday(&td, NULL);
  int64_t end_ms = td.tv_sec;
  end_ms = end_ms * 1000;
  usec = td.tv_usec;
  usec = usec / 1000;
  end_ms += usec;

  printf("Completed writing %d records in %g seconds\n", num_records * num_threads, (double)(end_ms - start_ms) / 1000.0);
  printf("  = %2g r/w operations per second\n", (double)(num_records * num_threads * 1000.0) / (double)(end_ms - start_ms));
  exit(0);
}
