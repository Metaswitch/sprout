#!/usr/bin/python
import os
from os.path import isfile, getsize, exists

ONE_KB=1024
ONE_GB=ONE_KB**3
ANALYTICS_MAX=ONE_GB
SPROUT_MAX=ONE_GB
BONO_MAX=ONE_GB
SPROUT_LOGDIR="/var/log/sprout/"
BONO_LOGDIR="/var/log/bono/"

def get_logs(dir, prefix):
    """Return a list of all files in dir which start with prefix"""
    if exists(dir):
        return [dir+i for i in os.listdir(dir)
                    if (isfile(dir+i) and i.startswith(prefix))]
    else:
        return []

def total(logfiles):
    """Return the total filesize, in bytes, of all files in logfiles"""
    return sum([getsize(f) for f in logfiles])

if __name__ == "__main__":

        # Define the log files to monitor
	sprout_logs = get_logs(SPROUT_LOGDIR, "sprout_")
	bono_logs = get_logs(BONO_LOGDIR, "bono_")
	sprout_analytics_logs = get_logs(SPROUT_LOGDIR, "log_")
	bono_analytics_logs = get_logs(BONO_LOGDIR, "log_")

	for logs, max_size in [(sprout_logs, SPROUT_MAX),
                           (bono_logs, BONO_MAX),
                           (sprout_analytics_logs, ANALYTICS_MAX),
                           (bono_analytics_logs, ANALYTICS_MAX)]:
	    size_to_delete = total(logs) - max_size
	    for logfile in sorted(logs):
		if (size_to_delete > 0):
		    size_to_delete -= getsize(logfile)
		    os.unlink(logfile)
