Miscellaneous Test Tools
========================

TCP Stress
----------

The TCP Stress tool (tcpstress) sets up as many concurrent connections to port 5060 of a target node (specified by IP address on the command-line) as it can.  It stops establishing TCP connections when it hits its first failure, either through a rejected connection, or through a timeout (of 3s).  It then prints the number of TCP connections it successfully established to screen and terminates.  This is useful for determining whether clouds (or specific nodes within clouds) have limits on the number of TCP connections they can make or receive.

Compilation instructions are at the top of tcpstress.c.  In order to run, you'll need to increase the maximum file descriptor limit - the tcpstress.sh script does this for you.  Run as "sudo tcpstress.sh <ip address>".
