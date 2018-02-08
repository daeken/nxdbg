from socket import *
import struct

class MemoryInfo(object):
	def __init__(self, data):
		self.addr, self.size, self.perm, self.type = struct.unpack('<QQII', data)

class SwitchException(Exception):
	def __init__(self, code):
		Exception.__init__(self, 'Switch call failed with 0x%x' % code)
		self.code = code

class DebugEvent(object):
	@staticmethod
	def parse(data):
		type, flags, tid = struct.unpack('<IIQ', data[:16])
		rest = data[16:]
		if type == 0:
			return ProcessAttachEvent(flags, tid, rest)
		elif type == 1:
			return ThreadAttachEvent(flags, tid, rest)
		elif type == 4:
			return ExceptionEvent.parse(flags, tid, rest)

		print 'DebugEvent not handled:', type, flags, tid
		print `data`

		return None

	def __init__(self, flags, tid):
		self.flags = flags
		self.tid = tid

class ProcessAttachEvent(DebugEvent):
	def __init__(self, flags, tid, data):
		DebugEvent.__init__(self, flags, tid)
		self.titleid, self.pid, name, self.mmuflags = struct.unpack('<QQ12sI', data[:32])
		self.name = name.split('\0', 1)[0]

	def __repr__(self):
		return 'ProcessAttachEvent(name=%r, titleid=0x%016x, pid=%i)' % (self.name, self.titleid, self.pid)

class ThreadAttachEvent(DebugEvent):
	def __init__(self, flags, tid, data):
		DebugEvent.__init__(self, flags, tid)
		self.tid, self.tls, self.func = struct.unpack('<QQQ', data[:24])

	def __repr__(self):
		return 'ThreadAttachEvent(tid=%i, tls=0x%x, func=0x%x)' % (self.tid, self.tls, self.func)

class ExceptionEvent(DebugEvent):
	@staticmethod
	def parse(flags, tid, data):
		type, faultreg, pe = struct.unpack('<QQQ', data[:24])
		return (
			UndefinedInstructionEvent, 
			InstructionAbortEvent, 
			DataAbortEvent, 
			PcSpAlignmentEvent, 
			DebuggerAttachedEvent, 
			BreakpointEvent, 
			UserBreakEvent, 
			DebuggerBreakEvent, 
			BadSvcEvent
		)[type](flags, tid, faultreg, pe)

	def __init__(self, flags, tid):
		self.flags, self.tid = flags, tid

class UndefinedInstructionEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.pc, self.opcode = faultreg, pe
	def __repr__(self):
		return 'UndefinedInstructionEvent(tid=%i, pc=0x%x, opcode=0x%08x)' % (self.tid, self.pc, self.opcode)

class InstructionAbortEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.pc = faultreg
	def __repr__(self):
		return 'InstructionAbortEvent(tid=%i, pc=0x%x)' % (self.tid, self.pc)

class DataAbortEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.addr = faultreg
	def __repr__(self):
		return 'DataAbortEvent(tid=%i, addr=0x%x)' % (self.tid, self.addr)

class PcSpAlignmentEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.addr = faultreg
	def __repr__(self):
		return 'PcSpAlignmentEvent(tid=%i, addr=0x%x)' % (self.tid, self.addr)

class DebuggerAttachedEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
	def __repr__(self):
		return 'DebuggerAttachedEvent()'

class BreakpointEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.isWatchdog = bool(pe)
	def __repr__(self):
		return 'BreakpointEvent(tid=%i, isWatchdog=%r)' % (self.tid, self.isWatchdog)

class UserBreakEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
	def __repr__(self):
		return 'UserBreakEvent(tid=%i)' % self.tid

class DebuggerBreakEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
	def __repr__(self):
		return 'DebuggerBreakEvent()'

class BadSvcEvent(ExceptionEvent):
	def __init__(self, flags, tid, faultreg, pe):
		ExceptionEvent.__init__(self, flags, tid)
		self.svc = pe
	def __repr__(self):
		return 'BadSvcEvent(tid=%i, svc=0x%x)' % (self.tid, self.svc)

class ThreadContext(object):
	def __init__(self, data):
		self.registers = struct.unpack('<' + 'Q' * 33, data[:8 * 33])

class Connection(object):
	def __init__(self, ip, port):
		self.sock = socket(AF_INET, SOCK_STREAM)
		self.sock.connect((ip, port))
		print 'Connected to %s:%i' % (ip, port)

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

	def sr(self, cmd, format='', *args):
		self.send(struct.pack('<I' + format, cmd, *args))

		result, size = struct.unpack('<II', self.recv(8))
		data = self.recv(size)
		if result != 0:
			raise SwitchException(result)
		return data

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
		return DebugEvent.parse(self.sr(4, 'I', handle))

	def readMemory(self, handle, addr, size):
		data = ''
		for i in xrange(0, size, 0x1000):
			data += self.sr(5, 'IIQ', handle, min(size - len(data), 0x1000), addr + len(data))
		return data

	def continueDebugEvent(self, handle, flags, tid):
		self.sr(6, 'IIQ', handle, flags, tid)

	def getThreadContext(self, handle, flags, tid):
		try:
			return ThreadContext(self.sr(7, 'IIQ', handle, flags, tid))
		except SwitchException:
			return None

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
		return struct.unpack('<Q', self.sr(13, 'Q', tid))[0]
