/**
 * @file tcpstress.c
 *
 * Copyright (C) 2013  Metaswitch Networks Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The author can be reached by email at clearwater@metaswitch.com or by post at
 * Metaswitch Networks Ltd, 100 Church St, Enfield EN2 6BQ, UK
 */

// Starts lots of TCP connections very quickly to port 5060 (SIP)
// Hacked together for testing a Clearwater bug.
// Usage: tcpstress <host>
// Compile: gcc -o tcpstress tcpstress.c

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <strings.h>
#include <errno.h>

int main(int argc, char **argv) {
  struct hostent *host;
  struct sockaddr_in sin;
  int cnt;
  int fd;
  int flags;
  struct pollfd pollfd;
  int rc;
  int fds[65536];

  host = gethostbyname(argv[1]);

  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  bcopy(host->h_addr, &sin.sin_addr.s_addr, host->h_length);
  sin.sin_port = htons(5060);

  for (cnt = 0; cnt < 65536; cnt++)
  {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
      perror("socket");
      break;
    }

    flags = fcntl(fd, F_GETFL, 0); 
    if (flags == -1)
    {
      perror("fcntl(F_GETFL)");
      break;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
      perror("fcntl(F_SETFL)");
      break;
    }

    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == -1)
    {
      if (errno != EINPROGRESS)
      {
        perror("connect");
        break;
      }

      bzero(&pollfd, sizeof(struct pollfd));
      pollfd.fd = fd;
      pollfd.events = POLLOUT;
      rc = poll(&pollfd, 1, 3000);
      if (rc == -1)
      {
        perror("poll");
        break;
      }
      else if (rc == 0)
      {
        fprintf(stderr, "connect: Connection timed out\n");
        break;
      }
    }

    fds[cnt] = fd;
    fd = 0;
  }

  printf("%d\n", cnt);

  if (fd != -1)
  {
    close(fd);
  }

  if (cnt == 65536) {
    cnt--;
  }
  while (cnt > 0) {
    close(fds[cnt]);
    cnt--;
  }

  return 0;
}
