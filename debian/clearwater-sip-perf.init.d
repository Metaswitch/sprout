#! /bin/sh

# @file clearwater-sip-perf.init.d
#
# Copyright (C) Metaswitch Networks 2015
# If license terms are provided to you in a COPYING file in the root directory
# of the source code repository by which you are accessing this code, then
# the license outlined in that COPYING file applies to your use.
# Otherwise no rights are granted except for those provided to you by
# Metaswitch Networks in a separate written agreement.

### BEGIN INIT INFO
# Provides:          clearwater-sip-perf
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Clearwater SIP performance test
# Description:       Runs SIP performance test against Clearwater
### END INIT INFO

# Author: Mike Evans <mike.evans@metaswitch.com>
#
# Please remove the "Author" lines above and replace them
# with your own name if you copy and modify this script.

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Clearwater SIP performance test"
NAME=sip-perf
PIDFILE=/var/run/$NAME.pid
DAEMON=/usr/share/clearwater/bin/sip-perf

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
#[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
        # Return
        #   0 if daemons have been started
        #   1 if some daemons were already running (and any others have been started)
        #   2 if some daemons could not be started (some may have been started)

        # Restart clearwater-infrastructure to pick up any config changes first.
        service clearwater-infrastructure restart

        start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
                || return 1

        start-stop-daemon --start --quiet --background --make-pidfile --pidfile $PIDFILE --exec $DAEMON \
                || return 2
}

#
# Function that stops the daemon/service
#
do_stop()
{
        start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE.$index --name $NAME
        RETVAL="$?"

        # Kill any remaining clearwater-sip-perf or sipp instances
        pkill clearwater-sip-perf >/dev/null 2>&1
        pkill sipp >/dev/null 2>&1

        return "$RETVAL"
}

#
# Function that runs the daemon/service
#
do_run()
{
        # Return
        #   0 if daemons have been started
        #   1 if some daemons were already running (and any others have been started)
        #   2 if some daemons could not be started (some may have been started)

        # Restart clearwater-infrastructure to pick up any config changes first.
        service clearwater-infrastructure restart

        $DAEMON
        RETVAL="$?"
        return "$RETVAL"
}

case "$1" in
  start)
        [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
        do_start
        case "$?" in
                0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
                2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  stop)
        [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
        case "$?" in
                0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
                2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  run)
        [ "$VERBOSE" != no ] && log_daemon_msg "Running $DESC" "$NAME"
        do_run
        case "$?" in
                0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
                2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
  status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
  restart|force-reload)
        #
        # If the "reload" option is implemented then remove the
        # 'force-reload' alias
        #
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_stop
        case "$?" in
          0|1)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        1) log_end_msg 1 ;; # Old process is still running
                        *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
  *)
        #echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
        exit 3
        ;;
esac

:
