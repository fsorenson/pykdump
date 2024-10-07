#!/usr/bin/python

import sys, os
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)

from fs_lib import *

def usage():
	print("usage: eval_time <value>")

if __name__ == "__main__":

	jiffies = readSymbol("jiffies")

	try:
		tk = readSymbol("timekeeper")
	except:
		tk = None
	if tk is None:
		try:
			tk_core = readSymbol("tk_core")
			real_tk = tk_core.timekeeper
			shadow_timekeeper = readSymbol("shadow_timekeeper")
			tk = shadow_timekeeper
		except:
			pass
	if tk is None:
		print("unable to determine timekeeper... attempting to proceed without")
		now_vmcore = 0
	else:
		try:
			now_vmcore = tk.xtime
		except:
			now_vmcore = tk.xtime_sec

	system_start_time = now_vmcore - (jiffies / 1000)
	now_current = time.time()

	start_time_str = "{}, or '{}'".format(system_start_time, timespec_to_string(system_start_time))
	system_uptime_str = "{} jiffies/{} seconds".format(jiffies, jiffies/1000)
	vmcore_time_str = "{}, or '{}'".format(now_vmcore, timespec_to_string(now_vmcore))
	current_time_str = "{}, or '{}'".format(now_current, timespec_to_string(now_current))

	print("")
	print("system start time: {}".format(start_time_str))
	print("system uptime: {}".format(system_uptime_str))

	print("Now (vmcore time) is {}".format(vmcore_time_str))
	print("jiffies: {}".format(jiffies))
	print("Now (current time) is {}, or '{}'".format(now_current, timespec_to_string(now_current)))
	print("")

	try:
		val = get_arg_value(sys.argv[1])
	except:
		val = None

	if val is not None:

#	print("address is 0x{a:016x}, object type is {o}, member is {m}".format(a=addr, o=sys.argv[2], m=sys.argv[3]))

		print("duration:")
		print("\t{} seconds duration: {}".format(val, pp_time_ms(int(val * 1000.0))))
		print("\t{} jiffies duration: {}".format(val, pp_time_ms(int(val))))

		print("timestamps:")
		print("\t{} ns: {}".format(val, timespec_to_string(val/1000000000.0)))
		print("\t{} seconds: {}".format(val, timespec_to_string(val)))

		print("time relative to system start ({})".format(timespec_to_string(now_vmcore - jiffies/1000)))
		print("\t{} jiffies from system start".format(jiffies))
		print("\t{} seconds after system start: {}".format(val, timespec_to_string(system_start_time + val)))
		print("\t{} jiffies after system start: {}".format(val, timespec_to_string(system_start_time + val/1000)))

		print("")
		print("prior to 'now' (vmcore time):")
		print("\t{} seconds: {} - '{}'".format(val, now_vmcore - val, timespec_to_string(now_vmcore - val)))
		print("\t{} jiffies: {} - '{}'".format(val, now_vmcore - (val/1000.0),
			timespec_to_string(now_vmcore - ((val * 1.0)/1000.0))))


		print("\nprior to 'now' (current time):")
		print("\t{} seconds: {} - '{}'".format(val, now_current - val, timespec_to_string(now_current - val)))
		print("\t{} jiffies: {} - '{}'".format(val, now_current - ((val * 1.0)/1000.0),
			timespec_to_string(now_current - ((val * 1.0)/1000.0))))

		print("")


#try:
#	import datetime
#	import time
#except:
#	print("no datetime?")
#	print("no time?")
#try:
#	lt = time.localtime(ts)


#seconds prior to now
#measured as jiffies prior to now
#seconds prior to crash time

#0x1428edc3e372225e



# vim: sw=4 ts=4 noexpandtab
