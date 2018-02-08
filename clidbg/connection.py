from socket import *
import struct

class MemoryInfo(object):
	def __init__(self, data):
		self.addr, self.size, self.perm, self.type = struct.unpack('<QQII', data)

class Connection(object):
	def __init__(self, host='', port=0xdead):
		serv = socket(AF_INET, SOCK_STREAM)
		serv.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		serv.bind(('', 0xdead))
		serv.listen(1)
		print 'Waiting for connection on %r:%i' % (host, port)
		self.sock, client = serv.accept()
		print 'Got connection'

	def recv(self, count):
		data = ''
		while len(data) < count:
			temp = self.sock.recv(count - len(data))
			if temp == '':
				raise Exception('Connection dead')
			data += temp
		return data

	def send(self, data):
		count = 0
		while count < len(data):
			count += self.sock.send(data[count:])

	def sr(self, cmd, format='', *args, throw=True):
		self.send(struct.pack('<I' + format, cmd, *args))
		return self.readresp(throw=throw)

	def readresp(self, throw=True):
		result, size = struct.unpack('<II', self.recv(8))
		data = self.recv(size)
		if result != 0 and throw:
			raise SwitchException(result)
		elif throw:
			return data
		return result, data

	def listProcesses(self):
		data = self.sr(0)
		return struct.unpack('<' + 'Q' * (len(data) / 8), data)

	def attachProcess(self, pid):
		return struct.unpack('<I', self.sr(1, 'Q', pid))[0]

	def detachProcess(self, handle):
		self.sr(2, 'I', handle)

	def queryMemory(self, handle, addr):
		return MemoryInfo(self.sr(3, 'IIQ', handle, 0, addr))

	def getDebugEvent(self, handle):
		return DebugEvent(self.sr(4, 'I', handle))

	def readMemory(self, handle, addr, size):
		data = ''
		for i in xrange(0, size, 0x1000):
			data += self.sr(5, 'IIQ', handle, min(size - len(data), 0x1000), addr + len(data))
		return data

	def continueDebugEvent(self, handle, flags, tid):
		self.sr(6, 'IIQ', handle, flags, tid)

	def getThreadContext(self, handle, flags, tid):
		return self.sr(7, 'IIQ', handle, flags, tid)

	def breakProcess(self, handle):
		self.sr(8, 'I', handle)

	def writeMemory32(self, handle, addr, value):
		self.sr(9, 'IIQ', handle, value, address)

	def waitForAppLaunch(self):
		self.sr(10)

	def getAppPid(self):
		return struct.unpack('<Q', self.sr(11))[0]

	def startProcess(self, pid):
		self.sr(12, 'Q', pid)

	def getTitlePid(self, tid):
		return struct.unpack('<Q', self.sr(13, 'Q', tid))
