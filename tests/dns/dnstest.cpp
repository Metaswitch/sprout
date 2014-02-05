#include <iostream>
#include <string>
#include <vector>

#include <getopt.h>
#include <arpa/inet.h>

#include "log.h"
#include "utils.h"
#include "dnscachedresolver.h"

void usage(char *command)
{
  printf("Blah");
}

void query(DnsCachedResolver& resolver, const std::string& name, const std::string& type)
{
  int dnstype;
  if (type == "A")
  {
    dnstype = ns_t_a;
  }
  else if (type == "AAAA")
  {
    dnstype = ns_t_aaaa;
  }
  else if (type == "SRV")
  {
    dnstype = ns_t_srv;
  }
  else if (type == "NAPTR")
  {
    dnstype = ns_t_naptr;
  }

  printf("Issuing query for %s type %s", name.c_str(), type.c_str());

  DnsResult result = resolver.dns_query(name, dnstype);

  printf("%ld results\n", result.records().size());

  printf("DNS Query for %s %s\n", name.c_str(), type.c_str());
  for (std::list<DnsRRecord*>::const_iterator i = result.records().begin();
       i != result.records().end();
       ++i)
  {
    printf("%s\n", (*i)->to_string().c_str());
  }
}

int main(int argc, char *argv[])
{
  std::map<int, std::string> rrtypes;
  rrtypes[1] = "A";
  rrtypes[18] = "AAAA";
  rrtypes[33] = "SRV";
  rrtypes[35] = "NAPTR";

  std::string server = "127.0.0.1";
  std::string name;
  std::string type = "A";
  int log_level = 2;

  // Check for a server override in the first parameter,
  if ((argc > 1) &&
      (*(argv[1]) == '@'))
  {
    server = std::string(argv[1] + 1);
    printf("Server is %s\n", server.c_str());
    optind++;
  }

  // Parse the command line options
  while (true)
  {
    printf("optind = %d\n", optind);
    static struct option long_options[] =
    {
      {"log-level",           required_argument,         0, 'L'},
      {0, 0, 0, 0}
    };

    // getopt_long stores the option index here.
    int option_index = 0;

    char c = getopt_long(argc, argv, "vs:t:r:p:L:", long_options, &option_index);

    // Detect the end of the options.
    if (c == -1)
    {
      break;
    }

    switch (c)
    {
      case 'L':
        log_level = atoi(optarg);
        break;

      default:
        usage(argv[0]);
        exit(1);
    }
  }

  if (optind < argc)
  {
    printf("Name is %s\n", argv[optind]);
    name = std::string(argv[optind]);
    ++optind;
  }

  if (optind < argc)
  {
    printf("Type is %s\n", argv[optind]);
    type = std::string(argv[optind]);
    ++optind;
  }

  Log::setLoggingLevel(log_level);
  Log::setLogger(new Logger());

  printf("Creating resolver\n");
  DnsCachedResolver resolver(server);

  if (name != "")
  {
    // Query specified on the command line, so issue the query and exit.
    query(resolver, name, type);
    printf("Cache status ...\n%s\n", resolver.display_cache().c_str());
  }
  else
  {
    // No query specified on the command line, so go in to interactive mode.
    while (true)
    {
      printf("Enter command (x, c, q, l): ");

      std::string cmd;
      getline(std::cin, cmd);
      std::vector<std::string> tokens;
      Utils::split_string(cmd, ' ', tokens);

      if (tokens.size() >= 1)
      {
        switch (tokens[0][0])
        {
          case 'x':
          case 'X':
            exit(0);

          case 'c':
          case 'C':
            printf("Cache status ...\n%s\n", resolver.display_cache().c_str());
            break;

          case 'l':
          case 'L':
            if (tokens.size() <= 1)
            {
              printf("Not enough parameters for log command\n");
            }
            else
            {
              int log_level = atoi(tokens[1].c_str());
              printf("Setting logging level to %d\n", log_level);
              Log::setLoggingLevel(log_level);
            }
            break;

          case 'q':
          case 'Q':
            if (tokens.size() <= 1)
            {
              printf("Not enough parameters for query command\n");
            }
            else
            {
              name = tokens[1];
              type = (tokens.size() >= 3) ? tokens[2] : "A";
              query(resolver, name, type);
            }
            break;

          default:
            printf("Unknown command %s - commands are x (exit), c (display cache) and q (query)\n", tokens[0].c_str());
            break;
        }
      }
    }
  }
  return 0;
}
