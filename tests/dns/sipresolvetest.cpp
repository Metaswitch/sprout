#include <iostream>
#include <string>
#include <vector>

#include <getopt.h>
#include <arpa/inet.h>

#include "log.h"
#include "utils.h"
#include "dnscachedresolver.h"
#include "sipresolver.h"

void usage(char *command)
{
  printf("Blah");
}

int get_transport(const char* t)
{
  if (strcasecmp(t, "TCP") == 0)
  {
    return IPPROTO_TCP;
  }
  else if (strcasecmp(t, "UDP") == 0)
  {
    return IPPROTO_UDP;
  }
  else
  {
    return -1;
  }
}

std::string addrinfo_to_string(const AddrInfo& ai)
{
  std::ostringstream oss;
  char buf[100];
  oss << inet_ntop(ai.address.af, &ai.address.addr, buf, sizeof(buf));
  oss << ":" << ai.port << ";transport=";
  if (ai.transport == IPPROTO_UDP)
  {
    oss << "UDP";
  }
  else if (ai.transport == IPPROTO_TCP)
  {
    oss << "TCP";
  }
  return oss.str();
}

void resolve(SIPResolver& sipresolver,
             const std::string& target,
             int af,
             int port,
             int transport,
             int retries,
             int repeats)
{
  std::vector<AddrInfo> servers;

  if (repeats == 1)
  {
    sipresolver.resolve(target, af, port, transport, retries, servers);
    if (servers.size() > 0)
    {
      printf("Resolution successful\n");
      for (size_t ii = 0; ii < servers.size(); ++ii)
      {
        printf("  %s\n", addrinfo_to_string(servers[ii]).c_str());
      }
    }
    else
    {
      printf("Resolution failed\n");
    }
  }
  else
  {
    std::map<std::string, std::vector<int> > counts;
    for (int ii = 0; ii < repeats; ++ii)
    {
      sipresolver.resolve(target, af, port, transport, retries, servers);

      if ((int)servers.size() > retries)
      {
        printf("Returned %ld servers when limit is %d\n", servers.size(), retries);
      }
      else if ((int)servers.size() < retries)
      {
        printf("Returned %ld servers when requested %d\n", servers.size(), retries);
      }

      // Successful.
      for (size_t jj = 0; jj < servers.size(); ++jj)
      {
        std::vector<int>& cv = counts[addrinfo_to_string(servers[jj])];

        if (cv.size() < jj + 1)
        {
          cv.resize(jj + 1);
        }
        cv[jj]++;
      }
    }
    printf("Completed %d resolutions finding %d unique destinations\n", repeats, (int)counts.size());
    for (std::map<std::string, std::vector<int>>::const_iterator i = counts.begin();
         i != counts.end();
         ++i)
    {
      printf("  %s :", i->first.c_str());
      const std::vector<int>& cv = i->second;
      for (int jj = 0; jj < retries; ++jj)
      {
        printf("  %3.2g%%", ((double)cv[jj]*100.0)/(double)repeats);
      }
      printf("\n");
    }
  }
}

int main(int argc, char *argv[])
{
  std::string server = "127.0.0.1";
  std::string target;
  int af = AF_INET;
  int port = 0;
  int transport = -1;
  int servers = 5;
  int repeats = 1;
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
    static struct option long_options[] =
    {
      {"tcp",                 no_argument,               0, 't'},
      {"TCP",                 no_argument,               0, 'T'},
      {"udp",                 no_argument,               0, 'u'},
      {"UDP",                 no_argument,               0, 'U'},
      {"port",                required_argument,         0, 'p'},
      {"servers",             required_argument,         0, 's'},
      {"repeat",              required_argument,         0, 'r'},
      {"log-level",           required_argument,         0, 'L'},
      {0, 0, 0, 0}
    };

    // getopt_long stores the option index here.
    int option_index = 0;

    char c = getopt_long(argc, argv, "46tup:s:r:L:", long_options, &option_index);

    // Detect the end of the options.
    if (c == -1)
    {
      break;
    }

    switch (c)
    {
      case '4':
        af = AF_INET;
        break;

      case '6':
        af = AF_INET6;
        break;

      case 't':
        transport = IPPROTO_TCP;
        break;

      case 'u':
        transport = IPPROTO_UDP;
        break;

      case 'p':
        port = atoi(optarg);
        break;

      case 's':
        servers = atoi(optarg);
        break;

      case 'r':
        repeats = atoi(optarg);
        break;

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
    printf("Target is %s\n", argv[optind]);
    target = std::string(argv[optind]);
    ++optind;
  }

  Log::setLoggingLevel(log_level);
  Log::setLogger(new Logger());

  printf("Creating DNS cache/resolver\n");
  DnsCachedResolver dns(server);

  printf("Creating SIP resolver\n");
  SIPResolver sipresolver(&dns);

  if (target != "")
  {
    // Query specified on the command line, so issue the query and exit.
    resolve(sipresolver, target, af, port, transport, servers, repeats);
  }
  else
  {
    // No query specified on the command line, so go in to interactive mode.
    while (true)
    {
      printf("Enter command (x=eXit, c=display Cache, r=Resolve, b=Blacklist, l=change Log level): ");

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
            printf("Cache status ...\n%s\n", dns.display_cache().c_str());
            break;

          case 'l':
          case 'L':
            if (tokens.size() < 2)
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

          case 'r':
          case 'R':
            if (tokens.size() < 2)
            {
              printf("Not enough parameters for resolve command\n");
            }
            else
            {
              target = tokens[1];
              port = (tokens.size() >= 3) ? atoi(tokens[2].c_str()) : 0;
              transport = (tokens.size() >= 4) ? get_transport(tokens[3].c_str()) : -1;
              servers = (tokens.size() >= 5) ? atoi(tokens[4].c_str()) : 5;
              repeats = (tokens.size() >= 6) ? atoi(tokens[5].c_str()) : 1;
              resolve(sipresolver, target, af, port, transport, servers, repeats);
            }
            break;

          case 'b':
          case 'B':
            if (tokens.size() < 4)
            {
              printf("Not enough parameters for blacklist command\n");
            }
            else
            {
              AddrInfo ai;
              inet_pton(AF_INET, tokens[1].c_str(), &ai.address.addr.ipv4);
              ai.address.af = af;
              ai.port = atoi(tokens[2].c_str());
              ai.transport = get_transport(tokens[3].c_str());
              sipresolver.blacklist(ai, 30);
              printf("Blacklisted %s for 30 seconds\n", addrinfo_to_string(ai).c_str());
            }
            break;

          default:
            printf("Unknown command %s\n", tokens[0].c_str());
            break;
        }
      }
    }
  }

  return 0;
}
