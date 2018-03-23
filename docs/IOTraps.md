# Trapping disallowed IO patterns

Sprout's overload controls use message latency to spot when sprout is under too much load. However these controls exclude the latency of any IO that sprout does when processing a message, so as to accurately measure the load on the sprout node and not other devices in the network. For this to work correctly, it is important that any IO done on a sprout worker thread is wrapped in calls to `CW_IO_STARTS` and `CW_IO_COMPLETES`, as this ensures that any latency incurred from the IO is deducted from the overall latency of the message.

In order to spot if sprout does any IO with making the above calls, sprout comes with an "IO trap". This is a shared object that can be installed into sprout using the `LD_PRELOAD` environment variable. With the trap installed, ff sprout's worker threads do any IO without making these calls, the process will abort and produce a stack trace and a core file.

To run sprout with the IO trap, do the following.

1.  Find the command line you are using to run sprout (`ps -eaf | grep sprout`)
1.  Make sure you have the appropriate debug packages installed (`sudo apt-get install sprout-node-dbg`)
1.  Disable monitoring of sprout (`sudo monit unmonitor -g sprout`)
1.  Stop sprout (`sudo service sprout stop`)
1.  Set user limits and become the sprout user (`sudo -i; ulimit -Hn 1000000; ulimit -Sn 1000000; ulimit -r 1; ulimit -c unlimited; sudo -s -u sprout bash`)
1.  Change to the `/etc/clearwater` directory
1.  Run the following command, replacing args with the arguments sprout was run with in step 1.

```
LD_PRELOAD=/usr/share/clearwater/sprout/lib/sprout_io_trap.so LD_LIBRARY_PATH=/usr/share/clearwater/sprout/lib /usr/share/clearwater/bin/sprout <args>
```
