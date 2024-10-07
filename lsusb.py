#!/usr/bin/python

from __future__ import print_function

import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	if mypath not in sys.path:
		sys.path.append(mypath)

from fs_lib import *
from file import *
from pykdump.API import *
#from misc.percpu import get_per_cpu


from LinuxDump.Tasks import TaskTable
from LinuxDump.fs.dcache import *
from LinuxDump.trees import *
from LinuxDump.idr import *


def ffs(x):
	"""Returns the index, counting from 1, of the
	least significant set bit in `x`.
	"""
	return (x&-x).bit_length()


#crash> list -H usb_bus_list -o usb_bus.bus_list -s usb_bus.busnum,bus_name,usbfs_dentry -r
#ffff880c288df738
#  busnum = 0x1
#  bus_name = 0xffff88182c806ed8 "0000:00:1a.0"
#  usbfs_dentry = 0xffff880c2a4ed070
#ffff880c288de708
#  busnum = 0x2
#  bus_name = 0xffff88182c806f48 "0000:00:1d.0"
#  usbfs_dentry = 0xffff880c2a4ecb60
#ffff880c28656ba0
#  busnum = 0x3
#  bus_name = 0xffff880c2c4f3b90 "0000:01:00.4"
#  usbfs_dentry = 0xffff880c2a4f5b60



# On newer kernels:
#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
#                                          RADIX_TREE_MAP_SHIFT))

#/* Height component in node->path */
#define RADIX_TREE_HEIGHT_SHIFT (RADIX_TREE_MAX_PATH + 1)
#define RADIX_TREE_HEIGHT_MASK  ((1UL << RADIX_TREE_HEIGHT_SHIFT) - 1)
# static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1]
RADIX_TREE_MAP_SIZE = None
RADIX_TREE_HEIGHT_MASK = None

_rnode = "struct radix_tree_node"
try:
	ti = getStructInfo(_rnode)["slots"].ti
	RADIX_TREE_MAP_SIZE = ti.dims[0]
	RADIX_TREE_MAP_MASK = RADIX_TREE_MAP_SIZE - 1
	RADIX_TREE_MAP_SHIFT = ffs(RADIX_TREE_MAP_SIZE) - 1
	RADIX_TREE_INDIRECT_PTR = 1
	height_to_maxindex = readSymbol("height_to_maxindex")
	# Are we on a kernel with 'radix_tree_node.path'?
	if (member_size(_rnode, "path") != -1):
            # Yes, we are
			RADIX_TREE_MAX_PATH = len(height_to_maxindex)-1
			RADIX_TREE_HEIGHT_SHIFT = RADIX_TREE_MAX_PATH + 1
			RADIX_TREE_HEIGHT_MASK = (1 << RADIX_TREE_HEIGHT_SHIFT) - 1
except:
	pass



def indirect_to_ptr(ptr):
#return (void *)((unsigned long)ptr & ~RADIX_TREE_INDIRECT_PTR);
	return (long(ptr) & ~RADIX_TREE_INDIRECT_PTR)


def radix_tree_nodes_orig(ptree):
	first_rnode = readSU("struct radix_tree_node", indirect_to_ptr(ptree.rnode))
	if (not first_rnode):
		return []
	pheight = ptree.height
	_offset = member_offset("struct radix_tree_node", "slots")
	_size = RADIX_TREE_MAP_SIZE * pointersize

	def walk_radix_node(rnode, height):
		arr = mem2long(readmem(rnode+_offset, _size), array=RADIX_TREE_MAP_SIZE)
		for i, s in enumerate(arr):
			if (not s):
				continue
			if (height == 1):
				yield s
			else:
				for s1 in walk_radix_node(s, height-1):
					yield s1
	return walk_radix_node(long(first_rnode), pheight)

def radix_tree_nodes(ptree):
	ptree = readSU("struct radix_tree_node", ptree)
	def get_nodes(addr):
		for l in exec_crash_command("tree -t ra 0x{:016x}".format(addr)).split("\n"):
			if l != '':
				a = get_arg_value(l)
				yield a
	nodes = get_nodes(ptree)
	return nodes

def struct__member_obj(struct_obj, member):
	try:
		if struct_obj.hasField(member):
			member_obj = struct_obj.Eval(member)
			return member_obj
	except:
		pass
	return None

def display_generic_struct_member(addr, member_name, rlvl=0, ilvl=0):
	member_obj = struct__member_obj(addr, member_name)
	if member_obj == None:
		return

	try:
		sym = member_obj.PYT_symbol
		if sym.startswith('struct '):
#			member_type = sym[7:]
			print("{}.{} - ({} *)0x{:016x}".format(indent_str(ilvl), member_name, sym, long(member_obj)))
			return
	except AttributeError:
		pass

	if type(member_obj) == type(0):
		print("{}.{} - {}".format(indent_str(ilvl), member_name, member_obj))
	elif isinstance(member_obj, SmartString):
		print("{}.{} - (char *){} - '{}'".format(indent_str(ilvl), member_name, member_obj.addr, member_obj))
	else:
		print("{}.{} - (unknown type: {}) 0x{:016x}".format(indent_str(ilvl), member_name, member_obj, long(member_obj)))

def get_xarray_tree(xa):
	ret = []
	for l in exec_crash_command("tree -t xa 0x{:016x}".format(xa)).splitlines():
			if l != '':
				addr = get_arg_value(l)
				ret.append(addr)
	return ret

_USB_CLASS_C = '''
#define USB_CLASS_PER_INTERFACE         0       /* for DeviceClass */
#define USB_CLASS_AUDIO                 1
#define USB_CLASS_COMM                  2
#define USB_CLASS_HID                   3
#define USB_CLASS_PHYSICAL              5
#define USB_CLASS_STILL_IMAGE           6
#define USB_CLASS_PRINTER               7
#define USB_CLASS_MASS_STORAGE          8
#define USB_CLASS_HUB                   9
#define USB_CLASS_CDC_DATA              0x0a
#define USB_CLASS_CSCID                 0x0b    /* chip+ smart card */
#define USB_CLASS_CONTENT_SEC           0x0d    /* content security */
#define USB_CLASS_VIDEO                 0x0e
#define USB_CLASS_WIRELESS_CONTROLLER   0xe0
#define USB_CLASS_PERSONAL_HEALTHCARE   0x0f
#define USB_CLASS_AUDIO_VIDEO           0x10
#define USB_CLASS_BILLBOARD             0x11
#define USB_CLASS_USB_TYPE_C_BRIDGE     0x12
#define USB_CLASS_MISC                  0xef
#define USB_CLASS_APP_SPEC              0xfe
#define USB_CLASS_VENDOR_SPEC           0xff
'''
USB_CLASS = CDefine(_USB_CLASS_C)
s_USB_CLASS = {k: v for k,v in USB_CLASS.items()}
def class_decode(usb_class):
	if usb_class == s_USB_CLASS['USB_CLASS_PER_INTERFACE']:
		return ">ifc"
	elif usb_class == s_USB_CLASS['USB_CLASS_AUDIO']:
		return "audio"
	elif usb_class == s_USB_CLASS['USB_CLASS_COMM']:
		return "comm."
	elif usb_class == s_USB_CLASS['USB_CLASS_HID']:
		return "HID"
	elif usb_class == s_USB_CLASS['USB_CLASS_PHYSICAL']:
		return "PID"
	elif usb_class == s_USB_CLASS['USB_CLASS_STILL_IMAGE']:
		return "still"
	elif usb_class == s_USB_CLASS['USB_CLASS_PRINTER']:
		return "print"
	elif usb_class == s_USB_CLASS['USB_CLASS_MASS_STORAGE']:
		return "stor."
	elif usb_class == s_USB_CLASS['USB_CLASS_HUB']:
		return "hub"
	elif usb_class == s_USB_CLASS['USB_CLASS_CDC_DATA']:
		return "data"
	elif usb_class == s_USB_CLASS['USB_CLASS_CSCID']:
		return "scard"
	elif usb_class == s_USB_CLASS['USB_CLASS_CONTENT_SEC']:
		return "c-sec"
	elif usb_class == s_USB_CLASS['USB_CLASS_VIDEO']:
		return "video"
	elif usb_class == s_USB_CLASS['USB_CLASS_WIRELESS_CONTROLLER']:
		return "wlcon"
	elif usb_class == s_USB_CLASS['USB_CLASS_PERSONAL_HEALTHCARE']:
		return "perhc"
	elif usb_class == s_USB_CLASS['USB_CLASS_AUDIO_VIDEO']:
		return "av"
	elif usb_class == s_USB_CLASS['USB_CLASS_BILLBOARD']:
		return "blbrd"
	elif usb_class == s_USB_CLASS['USB_CLASS_USB_TYPE_C_BRIDGE']:
		return "bridg"
	elif usb_class == s_USB_CLASS['USB_CLASS_MISC']:
		return "misc"
	elif usb_class == s_USB_CLASS['USB_CLASS_APP_SPEC']:
		return "app."
	elif usb_class == s_USB_CLASS['USB_CLASS_VENDOR_SPEC']:
		return "vend."
	else:
		return "unk."

usb_device_speed = EnumInfo("enum usb_device_speed")
s_usb_device_speed = {k: v for k,v in usb_device_speed.items()}

def usb_dump_device_descriptor(desc):
#	/* D:  Ver=xx.xx Cls=xx(sssss) Sub=xx Prot=xx MxPS=dd #Cfgs=dd */
#  "D:  Ver=%2x.%02x Cls=%02x(%-5s) Sub=%02x Prot=%02x MxPS=%2d #Cfgs=%3d\n";
	print("D:  Ver={:2x}.{:02x} Cls={:02x}({:5s}) Sub={:02x} Prot={:02x} MxPS={:2d} #Cfgs={:3d}".format(
		le16_to_cpu(desc.bcdUSB) >> 8, le16_to_cpu(desc.bcdUSB) & 0xff,
		le16_to_cpu(desc.bcdDevice), class_decode(desc.bDeviceClass),
		desc.bDeviceSubClass, desc.bDeviceProtocol,
		desc.bMaxPacketSize0, desc.bNumConfigurations))

#/* P:  Vendor=xxxx ProdID=xxxx Rev=xx.xx */
#  "P:  Vendor=%04x ProdID=%04x Rev=%2x.%02x\n";
	print("P:  Vendor={:04x} ProdID={:04x} Rev={:2x}.{:02x}".format(
		le16_to_cpu(desc.idVendor), le16_to_cpu(desc.idProduct),
		le16_to_cpu(desc.bcdDevice) >> 8, le16_to_cpu(desc.bcdDevice) & 0xff))

def usb_dump_device_strings(dev): # usb_device
	# format_string_manufacturer
	# /* S:  Manufacturer=xxxx */
	#   "S:  Manufacturer=%.100s\n";
	if dev.manufacturer:
		print("S:  Manufacturer={:s}".format(dev.manufacturer))
	#format_string_product
	#/* S:  Product=xxxx */
	#  "S:  Product=%.100s\n";
	if dev.product:
		print("S:  Product={:s}".format(dev.product))

	# format_string_serialnumber
	#/* S:  SerialNumber=xxxx */
	#  "S:  SerialNumber=%.100s\n";
	if dev.serial:
		print("S:  SerialNumber={:s}".format(dev.serial))

def usb_dump_config_descriptor(desc, active, speed):
	mul = 2
	if speed >= s_usb_device_speed['USB_SPEED_SUPER']:
		mul = 8
	#format_config[] =
	#/* C:  #Ifs=dd Cfg#=dd Atr=xx MPwr=dddmA */
	#  "C:%c #Ifs=%2d Cfg#=%2d Atr=%02x MxPwr=%3dmA\n";
	print("C:{:1s} #Ifs={:2d} Cfd#={:2d} Atr={:02x} MxPwr={:3d}mA".format(
		"*" if active else " ",
		desc.bNumInterfaces,
		desc.bConfigurationValue,
		desc.bmAttributes,
		desc.bMaxPower * mul))

def usb_dump_iad_descriptor(iad):
	try:
		#format_iad[] =
		#/* A:  FirstIf#=dd IfCount=dd Cls=xx(sssss) Sub=xx Prot=xx */
		#  "A:  FirstIf#=%2d IfCount=%2d Cls=%02x(%-5s) Sub=%02x Prot=%02x\n";
		print("A:  FirstIf#={:2d} IfCount={:2d} Cls={:2x}({:5s} Sub={:02x} Prot={:02x}".format(
			iad.bFirstInterface, iad.bInterfaceCount,
			iad.bFunctionClass, class_decode(iad.bFunctionClass),
			iad.bFunctionSubClass, iad.bFunctionProtocol))
	except Exception as e:
		print("exception: {}".format(e))


#define USB_ENDPOINT_DIR_MASK		0x80
#define USB_DIR_IN			0x80		/* to host */
#define USB_DIR_OUT			0		/* to device */
def usb_endpoint_dir_in(epd):
	return epd.bEndpointAddress & 0x80 == 0x80
def usb_endpoint_dir_out(epd):
	return epd.bEndpointAddress & 0x80 == 0

#define USB_ENDPOINT_MAXP_MASK	0x07ff
#define USB_EP_MAXP_MULT_SHIFT	11
#define USB_EP_MAXP_MULT_MASK	(3 << USB_EP_MAXP_MULT_SHIFT)
#define USB_EP_MAXP_MULT(m) \
def usb_endpoint_maxp(epd):
	return le16_to_cpu(epd.wMaxPacketSize) & 0x07ff
def usb_endpoint_maxp_mult(epd):
	maxp = le16_to_cpu(epd.wMaxPacketSize)
#	(((m) & USB_EP_MAXP_MULT_MASK) >> USB_EP_MAXP_MULT_SHIFT)
#	return USB_EP_MAXP_MULT(maxp) + 1;
#	return (((maxp) & (3 << USB_EP_MAXP_MULT_SHIFT)) >> USB_EP_MAXP_MULT_SHIFT)
	return (((maxp) & (3 << 11)) >> 11)

def usb_endpoint_type(epd):
	#define USB_ENDPOINT_XFERTYPE_MASK	0x03	/* in bmAttributes */
	return epd.bmAttributes & 0x03

# int speed, const struct usb_endpoint_descriptor *desc
def usb_dump_endpoint_descriptor(speed, desc):
	bandwidth = 1
	_dir = "I" if usb_endpoint_dir_in(desc) else "O"
	if speed == s_usb_device_speed['USB_SPEED_HIGH']:
		bandwidth = usb_endpoint_maxp_mult(desc)
	endpoint_type = usb_endpoint_type(desc)
#define USB_ENDPOINT_XFER_CONTROL	0
#define USB_ENDPOINT_XFER_ISOC		1
#define USB_ENDPOINT_XFER_BULK		2
#define USB_ENDPOINT_XFER_INT		3
#define USB_ENDPOINT_MAX_ADJUSTABLE	0x80
	interval = 0
	if endpoint_type == 0:
		_type = "Ctrl"
		_dir = "B"
		if speed == s_usb_device_speed['USB_SPEED_HIGH']:
			interval = desc.bInterval
	elif endpoint_type == 1:
		_type = "Isoc"
		interval = 1 << (desc.b_interval - 1)
	elif endpoint_type == 2:
		_type = "Bulk"
		if speed == s_usb_device_speed['USB_SPEED_HIGH'] and usb_endpoint_dir_out(desc):
			interval = desc.bInterval
	elif endpoint_type == 3:
		_type = "Int."
		if speed >= s_usb_device_speed['USB_SPEED_HIGH']:
			interval = 1 << (desc.bInterval - 1)
		else:
			interval = desc.bInterval
	else:
		return
	if speed >= s_usb_device_speed['USB_SPEED_HIGH']:
		interval = interval * 125
	else:
		interval = interval * 1000

	if interval % 1000:
		unit = "u"
	else:
		unit = "m"
		interval = interval / 1000
	#format_endpt[] =
	#/* E:  Ad=xx(s) Atr=xx(ssss) MxPS=dddd Ivl=D?s */
	#  "E:  Ad=%02x(%c) Atr=%02x(%-4s) MxPS=%4d Ivl=%d%cs\n";
	print("E:  Ad={:02x}({}) Atr={:02x}({:4s}) MxPS={:4d} Ivl={}{}s".format(
		desc.bEndpointAddress, _dir, desc.bmAttributes, _type,
		usb_endpoint_maxp(desc) * bandwidth, interval, unit))


# const struct usb_interface_cache *intfc, const struct usb_interface *iface, int setno)
def usb_dump_interface_descriptor(intfc, iface, setno):
	desc = intfc.altsetting[setno].desc
	active = 0
	driver_name = ""
	if iface:
		driver_name = iface.dev.driver.name if iface.dev.driver else "(none)"
		active = desc == iface.cur_altsetting.desc

	# format_iface[] =
	#/* I:  If#=dd Alt=dd #EPs=dd Cls=xx(sssss) Sub=xx Prot=xx Driver=xxxx*/
	#  "I:%c If#=%2d Alt=%2d #EPs=%2d Cls=%02x(%-5s) Sub=%02x Prot=%02x Driver=%s\n";
	try:
		print("I:{:1s} If#={:2d} Alt={:2d} #EPs={:2d} Cls={:02x}({:5s}) Sub={:02x} Prot={:02x} Driver={:s}".format(
			"*" if active else ' ',
			desc.bInterfaceNumber, desc.bAlternateSetting,
			desc.bNumEndpoints, desc.bInterfaceClass,
			class_decode(desc.bInterfaceClass),
			desc.bInterfaceSubClass, desc.bInterfaceProtocol,
			driver_name))
	except Exception as e:
		print("exception: {}".format(e))

# int speed, const struct usb_interface_cache *intfc, const struct usb_interface *iface, int setno
def usb_dump_interface(speed, intfc, iface, setno):
	desc = intfc.altsetting[setno]
	usb_dump_interface_descriptor(intfc, iface, setno)
	for i in range(desc.desc.bNumEndpoints):
		usb_dump_endpoint_descriptor(speed, desc.endpoint[i].desc)

def usb_dump_config(speed, config, active):
	if not config:
		print("(null Cfg. desc.)")
		return
	usb_dump_config_descriptor(config.desc, active, speed)
	#include/linux/usb.h
	#define USB_MAXINTERFACES	32
	#define USB_MAXIADS		(USB_MAXINTERFACES/2)
	for i in range(16):
		if config.intf_assoc[i] == 0:
			break
		usb_dump_iad_descriptor(config.intf_assoc[i])
	try:
#		print("{} interfaces".format(config.desc.bNumInterfaces))
		for i in range(config.desc.bNumInterfaces):
			intfc = config.intf_cache[i]
			interface = config.interface[i]
			for j in range(intfc.num_altsetting):
				usb_dump_interface(speed, intfc, interface, j)
	except Exception as e:
		print("exception in usb_dump_config: {}".format(e))

def usb_dump_desc(dev):
	usb_dump_device_descriptor(dev.descriptor)
	usb_dump_device_strings(dev)
	for i in range(dev.descriptor.bNumConfigurations):
#		print("dump config for {}".format(i))
		usb_dump_config(dev.speed, dev.config + i,
			(dev.config + i) == dev.actconfig)



def dev_get_drvdata(dev):
	return dev.driver_data

def usb_get_intfdata(intf): # struct usb_interface *
	return dev_get_drvdata(intf.dev)

#struct usb_hub *usb_hub_to_struct_hub(struct usb_device *hdev)
def usb_hub_to_struct_hub(hdev):
	try:
		if not hdev or not hdev.actconfig or not hdev.maxchild:
			ret = 0
		else:
			ret = usb_get_intfdata(hdev.actconfig.interface[0])
		return readSU("struct usb_hub", ret)
	except Exception as e:
		print("exception in usb_hub_to_struct_hub: {}".format(e))

#struct usb_device *usb_hub_find_child(struct usb_device *hdev, int port1
def usb_hub_find_child(hdev, port1):
	try:
		hub = usb_hub_to_struct_hub(hdev)
#		print("usb_hub_find_child(0x{:016x}, {}) - (struct usb_hub *)0x{:016x}".format(hdev, port1, hub))

		if (port1 < 1 or port1 > hdev.maxchild):
			return 0
		return hub.ports[port1 - 1].child
	except Exception as e:
		print("exception in usb_hub_find_child: {}".format(e))

def usb_device_dump(usbdev, bus, level, index, count):
#	print("usb_device_dump(0x{:016x}".format(usbdev))
	parent_devnum = 0
	if usbdev.parent and usbdev.parent.devnum != -1:
		parent_devnum = usbdev.parent.devnum

	if usbdev.speed == s_usb_device_speed['USB_SPEED_LOW']:
		speed = "1.5"
	elif usbdev.speed == s_usb_device_speed['USB_SPEED_UNKNOWN'] or usbdev.speed == s_usb_device_speed['USB_SPEED_FULL']:
		speed = "12"
	elif usbdev.speed == s_usb_device_speed['USB_SPEED_WIRELESS'] or usbdev.speed == s_usb_device_speed['USB_SPEED_HIGH']:
		speed = "480"
	elif usbdev.speed == s_usb_device_speed['USB_SPEED_SUPER']:
		speed = "5000"
	elif usbdev.speed == s_usb_device_speed['USB_SPEED_SUPER_PLUS']:
		speed = "10000"
	else:
		speed = "??"

	#/* T:  Bus=dd Lev=dd Prnt=dd Port=dd Cnt=dd Dev#=ddd Spd=dddd MxCh=dd */
	#"\nT:  Bus=%2.2d Lev=%2.2d Prnt=%2.2d Port=%2.2d Cnt=%2.2d Dev#=%3d Spd=%-4s MxCh=%2d\n";
	print("\nT:  Bus={:02d} Lev={:02d} Prnt={:02d} Port={:02d} Cnt={:02d} Dev#={:03d} Spd={:4s} MxCh={:2d}".format(
		bus.busnum, level, parent_devnum, index, count, usbdev.devnum, speed, usbdev.maxchild))

	if level == 0: # root hub
		# include/linux/usb/hcd.h
		# define FRAME_TIME_USECS        1000L
		# define FRAME_TIME_MAX_USECS_ALLOC	(90L * FRAME_TIME_USECS / 100L)
		_max = (90 * 1000) / 100
		if usbdev.speed == s_usb_device_speed['USB_SPEED_HIGH'] or usbdev.speed >= s_usb_device_speed['USB_SPEED_SUPER']:
			_max = 800

		# format_bandwidth
		#/* B:  Alloc=ddd/ddd us (xx%), #Int=ddd, #Iso=ddd */
		#  "B:  Alloc=%3d/%3d us (%2d%%), #Int=%3d, #Iso=%3d\n";
		print("B:  Alloc={:3d}/{:3d} us ({:2d}%), #Int={:3d}, #Iso={:3d}".format(
			bus.bandwidth_allocated, _max, int((100 * bus.bandwidth_allocated + _max / 2) / _max),
			bus.bandwidth_int_reqs, bus.bandwidth_isoc_reqs))

	usb_dump_desc(usbdev)

	hdev = usbdev
	port1 = 1
	cnt = 0
	try:
#		print("hdev: 0x{:016x}".format(hdev))
		child = usb_hub_find_child(hdev, port1)
		while port1 <= hdev.maxchild:
#			print("child: 0x{:016x}".format(child))
			port1 = port1 + 1
			child = usb_hub_find_child(hdev, port1)
			if not child or child == None:
				continue
			chix = port1
			cnt = cnt + 1
			usb_device_dump(child, bus, level + 1, chix - 1, cnt)
	except Exception as e:
		print("exception in usb_device_dump: {}".format(e))



	# look at each of the device's children:
#	usb_hub_for_each_child(usbdev, chix, childdev) {
#			ret = usb_device_dump(buffer, nbytes, skip_bytes,
#			  file_offset, childdev, bus,
#			  level + 1, chix - 1, ++cnt);



def do_display_usb_buses():
	try:
		usb_bus_idr = readSymbol("usb_bus_idr")

	except Exception as e:
		print("exception in do_display_usb_buses: {}".format(e))
		return

#	try:
#		tree_addrs = get_xarray_tree(usb_bus_idr.idr_rt)
#		print("xarray_tree: {}".format(len(tree_addrs)))
#
#		for bus in tree_addrs:
#			bus = readSU("struct usb_bus", bus)
#			print("(struct usb_bus *)0x{:016x}  bus: {} ({})".format(bus, bus.busnum, bus.bus_name))
#	except:
#		return


	buses = []
	try:
#		print("thing 2")
		for _id, val in idr_for_each(usb_bus_idr):
#			print("id: {}\n".format(_id))
			bus = readSU("struct usb_bus", val)
#			print("thing: {}  0x{:016x}".format(bus.busnum, bus))
			buses.append(bus)
	except Exception as e:
		print("exception in do_display_usb_buses: {}".format(e))
		return

	try:
		for bus in buses:
			rh = bus.root_hub # usb_device
			usb_device_dump(bus.root_hub, bus, 0, 0, 0)
	except Exception as e:
		print("exception in do_display_usb_buses: {}".format(e))
		return



if __name__ == "__main__":
#	addr = get_arg_value(argv[x])
	do_display_usb_buses()

# vim: sw=4 ts=4 noexpandtab
