#!/usr/bin/python

from __future__ import print_function

import argparse
import sys, os

if __name__ == "__main__":
	mypath = os.path.dirname(os.path.realpath(sys.argv[0]))
	if mypath not in sys.path:
		sys.path.append(mypath)

from sorenson_lib import *
from pykdump.API import *

from LinuxDump.Tasks import TaskTable
from LinuxDump.fs.dcache import *
from LinuxDump.trees import *
from LinuxDump.idr import *

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
	return (long(ptr) & ~RADIX_TREE_INDIRECT_PTR)

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
	cnt = 0
	try:
		for port1 in range(1, hdev.maxchild + 1):
			child = usb_hub_find_child(hdev, port1)
			if not child or child == None:
				continue
			cnt = cnt + 1
			usb_device_dump(child, bus, level + 1, port1 - 1, cnt)
	except Exception as e:
		print("exception in usb_device_dump: {}".format(e))

	# look at each of the device's children:
#	usb_hub_for_each_child(usbdev, chix, childdev) {
#			ret = usb_device_dump(buffer, nbytes, skip_bytes,
#			  file_offset, childdev, bus,
#			  level + 1, chix - 1, ++cnt);



USB_IDS_PATHS = [
	"/usr/share/hwdata/usb.ids",
	"/usr/share/misc/usb.ids",
]


class UsbIdsDB(object):
	"""Parser and lookup table for usb.ids."""

	def __init__(self, path=None):
		self.vendors = {}
		self.products = {}
		self.classes = {}
		self.subclasses = {}
		self.prots = {}

		candidates = [path] if path else USB_IDS_PATHS
		for p in candidates:
			if p and os.path.isfile(p):
				self._load(p)
				break

	def _load(self, path):
		cur_vendor = None
		cur_class = None
		cur_sub = None
		in_classes = False

		with open(path, "r", encoding="utf-8", errors="replace") as f:
			for raw in f:
				line = raw.rstrip("\r\n")
				if not line or line.startswith("#"):
					continue
				if line.startswith("C "):
					in_classes = True
					cur_vendor = None
					parts = line[2:].strip().split(None, 1)
					if len(parts) == 2:
						try:
							cur_class = int(parts[0], 16)
							self.classes[cur_class] = parts[1]
							cur_sub = None
						except ValueError:
							cur_class = None
					continue

				if in_classes:
					if line.startswith("\t\t") and cur_class is not None and cur_sub is not None:
						parts = line[2:].strip().split(None, 1)
						if len(parts) == 2:
							try:
								self.prots[(cur_class, cur_sub, int(parts[0], 16))] = parts[1]
							except ValueError:
								pass
					elif line.startswith("\t") and cur_class is not None:
						parts = line[1:].strip().split(None, 1)
						if len(parts) == 2:
							try:
								cur_sub = int(parts[0], 16)
								self.subclasses[(cur_class, cur_sub)] = parts[1]
							except ValueError:
								cur_sub = None
					elif not line.startswith("\t"):
						in_classes = False
					else:
						continue

				if not in_classes:
					if line.startswith("\t") and not line.startswith("\t\t") and cur_vendor is not None:
						parts = line[1:].strip().split(None, 1)
						if len(parts) == 2:
							try:
								self.products[(cur_vendor, int(parts[0], 16))] = parts[1]
							except ValueError:
								pass
					elif not line.startswith("\t"):
						parts = line.strip().split(None, 1)
						if len(parts) == 2:
							try:
								cur_vendor = int(parts[0], 16)
								self.vendors[cur_vendor] = parts[1]
							except ValueError:
								cur_vendor = None

	def vendor_name(self, vid, fallback=""):
		return self.vendors.get(vid, fallback or "")

	def product_name(self, vid, pid, fallback=""):
		return self.products.get((vid, pid), fallback or "")

	def class_name(self, cls):
		return self.classes.get(cls, "[unknown]")

	def subclass_name(self, cls, sub):
		return self.subclasses.get((cls, sub), "[unknown]")

	def prot_name(self, cls, sub, prot):
		return self.prots.get((cls, sub, prot), "")


def get_usb_buses():
	usb_bus_idr = readSymbol("usb_bus_idr")
	buses = []
	for _id, val in idr_for_each(usb_bus_idr):
		buses.append(readSU("struct usb_bus", val))
	buses.sort(key=lambda b: int(b.busnum))
	return buses


def collect_bus_devices(usbdev, bus, level=0, port=1, out=None):
	if out is None:
		out = []
	out.append((bus, usbdev, level, port))
	for port1 in range(1, int(usbdev.maxchild) + 1):
		child = usb_hub_find_child(usbdev, port1)
		if child:
			collect_bus_devices(child, bus, level + 1, port1, out)
	return out


def format_bcd(bcd):
	val = int(bcd)
	return "{:x}.{:02x}".format((val >> 8) & 0xff, val & 0xff)


def speed_mbps_str(speed):
	if speed == s_usb_device_speed['USB_SPEED_LOW']:
		return "1.5M"
	if speed in (s_usb_device_speed['USB_SPEED_UNKNOWN'], s_usb_device_speed['USB_SPEED_FULL']):
		return "12M"
	if speed in (s_usb_device_speed['USB_SPEED_WIRELESS'], s_usb_device_speed['USB_SPEED_HIGH']):
		return "480M"
	if speed == s_usb_device_speed['USB_SPEED_SUPER']:
		return "5000M"
	if speed == s_usb_device_speed['USB_SPEED_SUPER_PLUS']:
		return "10000M"
	return "?M"


def device_id_label(usbdev, db):
	desc = usbdev.descriptor
	vid = int(desc.idVendor)
	pid = int(desc.idProduct)
	vname = db.vendor_name(vid, str(usbdev.manufacturer) if usbdev.manufacturer else "")
	pname = db.product_name(vid, pid, str(usbdev.product) if usbdev.product else "")
	label = "{:04x}:{:04x}".format(vid, pid)
	if vname:
		label += " " + vname
	if pname:
		label += " " + pname
	return label


def do_lsusb_default(buses, db):
	for bus in buses:
		devs = collect_bus_devices(bus.root_hub, bus)
		for b, dev, _, _ in sorted(devs, key=lambda x: int(x[1].devnum)):
			print("Bus {:03d} Device {:03d}: ID {}".format(
				int(b.busnum), int(dev.devnum), device_id_label(dev, db)
			))


def do_lsusb_tree(buses, db, verbose=False):
	def render_node(bus, dev, level, port):
		indent = "    " * level
		spd = speed_mbps_str(int(dev.speed))
		if level == 0:
			drv = ""
			try:
				if bus.controller and bus.controller.driver:
					drv = str(bus.controller.driver.name)
			except Exception:
				pass
			if not drv:
				drv = "usb"
			print("/:  Bus {:03d}.Port 001: Dev {:03d}, Class=root_hub, Driver={}/{}p, {}".format(
				int(bus.busnum), int(dev.devnum), drv, int(dev.maxchild), spd
			))
			if verbose:
				print("    ID {}".format(device_id_label(dev, db)))
		else:
			cfg = dev.actconfig
			if cfg and int(cfg.desc.bNumInterfaces) > 0:
				for i in range(int(cfg.desc.bNumInterfaces)):
					iface = cfg.interface[i]
					idesc = iface.cur_altsetting.desc
					cls_str = db.class_name(int(idesc.bInterfaceClass))
					drv = str(iface.dev.driver.name) if iface.dev.driver else "(none)"
					print("{}|__ Port {:03d}: Dev {:03d}, If {:d}, Class={}, Driver={}, {}".format(
						indent, port, int(dev.devnum), int(idesc.bInterfaceNumber), cls_str, drv, spd
					))
			else:
				cls_str = db.class_name(int(dev.descriptor.bDeviceClass))
				print("{}|__ Port {:03d}: Dev {:03d}, If 0, Class={}, Driver=(none), {}".format(
					indent, port, int(dev.devnum), cls_str, spd
				))
			if verbose:
				print("{}    ID {}".format(indent, device_id_label(dev, db)))

		for port1 in range(1, int(dev.maxchild) + 1):
			child = usb_hub_find_child(dev, port1)
			if child:
				render_node(bus, child, level + 1, port1)

	for bus in buses:
		render_node(bus, bus.root_hub, 0, 1)


def do_lsusb_verbose(buses, db):
	xfer_types = {0: "Control", 1: "Isochronous", 2: "Bulk", 3: "Interrupt"}
	sync_types = {0: "None", 1: "Asynchronous", 2: "Adaptive", 3: "Synchronous"}
	usage_types = {0: "Data", 1: "Feedback", 2: "Implicit Feedback Data", 3: "Reserved"}

	for bus in buses:
		devs = collect_bus_devices(bus.root_hub, bus)
		for b, dev, _, _ in sorted(devs, key=lambda x: int(x[1].devnum)):
			d = dev.descriptor
			vid = int(d.idVendor)
			pid = int(d.idProduct)
			bcls = int(d.bDeviceClass)
			bsub = int(d.bDeviceSubClass)
			bprot = int(d.bDeviceProtocol)
			mfg = str(dev.manufacturer) if dev.manufacturer else ""
			prod = str(dev.product) if dev.product else ""
			ser = str(dev.serial) if dev.serial else ""

			print("\nBus {:03d} Device {:03d}: ID {}".format(
				int(b.busnum), int(dev.devnum), device_id_label(dev, db)
			))
			print("Device Descriptor:")
			print("  bLength                {:d}".format(int(d.bLength)))
			print("  bDescriptorType         {:d}".format(int(d.bDescriptorType)))
			print("  bcdUSB               {}".format(format_bcd(d.bcdUSB)))
			print("  bDeviceClass            {:d} {}".format(bcls, db.class_name(bcls)))
			print("  bDeviceSubClass         {:d} {}".format(bsub, db.subclass_name(bcls, bsub)))
			print("  bDeviceProtocol         {:d} {}".format(bprot, db.prot_name(bcls, bsub, bprot)))
			print("  bMaxPacketSize0        {:d}".format(int(d.bMaxPacketSize0)))
			print("  idVendor           0x{:04x} {}".format(vid, db.vendor_name(vid, mfg)))
			print("  idProduct          0x{:04x} {}".format(pid, db.product_name(vid, pid, prod)))
			print("  bcdDevice            {}".format(format_bcd(d.bcdDevice)))
			print("  iManufacturer           {:d} {}".format(int(d.iManufacturer), mfg))
			print("  iProduct                {:d} {}".format(int(d.iProduct), prod))
			print("  iSerial                 {:d} {}".format(int(d.iSerialNumber), ser))
			print("  bNumConfigurations      {:d}".format(int(d.bNumConfigurations)))

			for ci in range(int(d.bNumConfigurations)):
				cfg = dev.config + ci
				cd = cfg.desc
				bm = int(cd.bmAttributes)
				print("  Configuration Descriptor:")
				print("    bLength                 {:d}".format(int(cd.bLength)))
				print("    bDescriptorType         {:d}".format(int(cd.bDescriptorType)))
				print("    wTotalLength       0x{:04x}".format(int(cd.wTotalLength)))
				print("    bNumInterfaces          {:d}".format(int(cd.bNumInterfaces)))
				print("    bConfigurationValue     {:d}".format(int(cd.bConfigurationValue)))
				print("    iConfiguration          {:d} {}".format(int(cd.iConfiguration), str(cfg.string) if cfg.string else ""))
				print("    bmAttributes         0x{:02x}".format(bm))
				if bm & 0x40:
					print("      Self Powered")
				else:
					print("      (Bus Powered)")
				if bm & 0x20:
					print("      Remote Wakeup")
				pwr_mult = 8 if int(dev.speed) >= s_usb_device_speed['USB_SPEED_SUPER'] else 2
				print("    MaxPower              {:3d}mA".format(int(cd.bMaxPower) * pwr_mult))

				for ii in range(int(cd.bNumInterfaces)):
					intfc = cfg.intf_cache[ii]
					for ai in range(int(intfc.num_altsetting)):
						alt = intfc.altsetting[ai]
						idsc = alt.desc
						icls = int(idsc.bInterfaceClass)
						isub = int(idsc.bInterfaceSubClass)
						iprot = int(idsc.bInterfaceProtocol)
						print("    Interface Descriptor:")
						print("      bLength                 {:d}".format(int(idsc.bLength)))
						print("      bDescriptorType         {:d}".format(int(idsc.bDescriptorType)))
						print("      bInterfaceNumber        {:d}".format(int(idsc.bInterfaceNumber)))
						print("      bAlternateSetting       {:d}".format(int(idsc.bAlternateSetting)))
						print("      bNumEndpoints           {:d}".format(int(idsc.bNumEndpoints)))
						print("      bInterfaceClass         {:d} {}".format(icls, db.class_name(icls)))
						print("      bInterfaceSubClass      {:d} {}".format(isub, db.subclass_name(icls, isub)))
						print("      bInterfaceProtocol      {:d} {}".format(iprot, db.prot_name(icls, isub, iprot)))
						print("      iInterface              {:d} {}".format(int(idsc.iInterface), str(alt.string) if alt.string else ""))

						for ei in range(int(idsc.bNumEndpoints)):
							ed = alt.endpoint[ei].desc
							ep_addr = int(ed.bEndpointAddress)
							ep_bm = int(ed.bmAttributes)
							maxp = int(ed.wMaxPacketSize)
							print("      Endpoint Descriptor:")
							print("        bLength                 {:d}".format(int(ed.bLength)))
							print("        bDescriptorType         {:d}".format(int(ed.bDescriptorType)))
							print("        bEndpointAddress     0x{:02x}  EP {:d} {}".format(
								ep_addr, ep_addr & 0x0f, "IN" if (ep_addr & 0x80) else "OUT"
							))
							print("        bmAttributes            {:d}".format(ep_bm))
							print("          Transfer Type            {}".format(xfer_types.get(ep_bm & 0x03, "?")))
							print("          Synch Type               {}".format(sync_types.get((ep_bm >> 2) & 0x03, "?")))
							print("          Usage Type               {}".format(usage_types.get((ep_bm >> 4) & 0x03, "?")))
							print("        wMaxPacketSize     0x{:04x}  {:d}x {:d} bytes".format(
								maxp, ((maxp >> 11) & 0x03) + 1, maxp & 0x07ff
							))
							print("        bInterval              {:2d}".format(int(ed.bInterval)))

			if bcls == 9 and dev.maxchild:
				try:
					hub = usb_hub_to_struct_hub(dev)
					if hub and hub.descriptor:
						hd = hub.descriptor
						print("Hub Descriptor:")
						print("  bLength              {:2d}".format(int(hd.bDescLength)))
						print("  bDescriptorType      {:2d}".format(int(hd.bDescriptorType)))
						print("  nNbrPorts            {:2d}".format(int(hd.bNbrPorts)))
						print("  wHubCharacteristic 0x{:04x}".format(int(hd.wHubCharacteristics)))
						print("  bPwrOn2PwrGood       {:2d} * 2 milli seconds".format(int(hd.bPwrOn2PwrGood)))
						print("  bHubContrCurrent     {:2d} milli Ampere".format(int(hd.bHubContrCurrent)))
				except Exception:
					pass


# this is really more like the 'usb-devices' program
def do_display_usb_buses():
	try:
		usb_bus_idr = readSymbol("usb_bus_idr")

	except Exception as e:
		print("exception in do_display_usb_buses: {}".format(e))
		return

	buses = []
	try:
		for _id, val in idr_for_each(usb_bus_idr):
			bus = readSU("struct usb_bus", val)
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
	parser = argparse.ArgumentParser(
		prog="lsusb",
		description="Display USB buses and devices from a Linux vmcore (lsusb / usb-devices).",
	)
	parser.add_argument("-t", "--tree", action="store_true", help="Dump the physical USB device hierarchy as a tree")
	parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity (show descriptors or tree IDs)")
	parser.add_argument("-U", "--usb-devices", action="store_true", help="Use usb-devices output format")
	parser.add_argument("-i", dest="ids_file", help="Use specified usb.ids file")
	args = parser.parse_args()

	if args.usb_devices:
		do_display_usb_buses()
	else:
		db = UsbIdsDB(args.ids_file)
		buses = get_usb_buses()
		if args.tree:
			do_lsusb_tree(buses, db, verbose=args.verbose)
		elif args.verbose:
			do_lsusb_verbose(buses, db)
		else:
			do_lsusb_default(buses, db)

# vim: sw=4 ts=4 noexpandtab
