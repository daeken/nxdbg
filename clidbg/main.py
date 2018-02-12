from cmd import Cmd
import argparse, re, sys, time
from capstone import *
try:
	try:
		import gnureadline as readline
	except ImportError:
		import readline
except ImportError:
	pass

from connection import *

class ResolutionException(Exception):
	pass

EXPR = 'expr'
PLAIN = 'plain'
REST = 'rest'

class Clidbg(Cmd):
	def __init__(self, ip, port):
		Cmd.__init__(self)

		self.lastEvent = None
		self.context = None
		self.swbreakpoints = {}
		self.dbg = Connection(ip, port)

		self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

		self.updatePrompt()

	def resolve(self, expr):
		if re.search(r'(\[|\.|\'|"|[a-zA-Z0-9_)]\s*\()', expr, re.M):
			raise ResolutionException('Invalid expression')

		if '$' in expr and self.context is None:
			raise ResolutionException('No current thread context')
		expr = re.sub(r'\$([a-zA-Z0-9]+)', lambda x: '(context.%s)' % x.group(1).lower(), expr)

		try:
			return eval(expr, {}, dict(context=self.context))
		except:
			raise ResolutionException('Invalid expression')

	def parseLine(self, line, format, defaults=None):
		def resolveOne(line):
			line = line.split(' ')
			if len(line) == 1:
				return self.resolve(line[0]), ''
			expr = ''
			ops = '+-*/%^&|<>='
			while len(line):
				if line[0] == '':
					line = line[1:]
					continue
				expr += ' ' + line[0]
				temp = line
				line = line[1:]
				if (len(temp) == 1 or (len(temp) > 1 and temp[0][-1] not in ops and temp[1][0] not in ops)) and expr.count(')') == expr.count('('):
					break
			return self.resolve(expr), ' '.join(line)

		ret = []
		defaults = () if defaults is None else defaults
		for elem in format:
			line = line.strip()
			if line == '':
				break
			if elem == EXPR:
				elem, line = resolveOne(line)
			elif elem == PLAIN:
				sub = line.split(' ', 1)
				if len(sub) == 1:
					elem, line = sub[0], ''
				else:
					elem, line = sub
			elif elem == REST:
				elem, line = line, ''
			else:
				assert False
			ret.append(elem)
		if len(ret) < len(format):
			ret += defaults[len(ret) - len(format):]
			if len(ret) != len(format):
				raise ResolutionException('Not enough arguments')
		return ret

	def updatePrompt(self):
		if self.context is None:
			self.prompt = 'nx> '
		else:
			self.prompt = '[%i] nx 0x%x> ' % (self.context.tid, self.context.pc)

	def print_topics(self, header, cmds, cmdlen, maxcol):
		nix = 'EOF', 
		if header is not None:
			Cmd.print_topics(self, header, [cmd for cmd in cmds if cmd not in nix], cmdlen, maxcol)

	def postcmd(self, stop, line):
		self.updatePrompt()
		return stop

	def do_EOF(self, line):
		print
		try:
			if raw_input('Really exit? y/n: ').startswith('y'):
				sys.exit()
		except EOFError:
			print
			sys.exit()

	def do_attachtitle(self, line):
		tid = int(line, 16)
		print 'Finding process with title ID %016x' % tid
		pid = self.dbg.getTitlePid(tid)
		print 'Title has PID %i' % pid
		self.do_attach(pid)

	def do_attach(self, line):
		pid = int(line)
		print 'Attempting to attach to pid %i' % pid
		try:
			self.phandle = self.dbg.attachProcess(pid)
		except:
			import traceback
			traceback.print_exc()
		print 'Attached'

	def do_break(self, line=None):
		print 'Breaking process'
		self.dbg.breakProcess(self.phandle)

	def do_continue(self, line=None):
		print 'Continuing...'

		if self.lastEvent is not None and self.lastEvent.flags & 1:
			try:
				self.dbg.continueDebugEvent(self.phandle, 7, 0)
			except SwitchException:
				pass
		self.lastEvent = None

		self.dbgone()

	def do_exit(self, line):
		"""exit
		Exit the debugger."""
		print line
		sys.exit()

	def do_registers(self, line):
		if self.context is None:
			print 'No current thread context'
			return
		for i in xrange(33):
			if i == 31:
				reg = 'SP'
			elif i == 32:
				reg = 'PC'
			else:
				reg = 'X%i' % i
			reg += ' ' if len(reg) == 2 else ''
			print '%s %016x   ' % (reg, self.context.registers[i]), 
			if i & 1:
				print
		if i & 1 == 0:
			print

	def do_hexdump(self, line):
		try:
			addr, size = self.parseLine(line, (EXPR, EXPR), (0x100, ))
		except ResolutionException, e:
			print e
			return

		data = self.dbg.readMemory(self.phandle, addr, size) if size > 0 else ''
		if data is None:
			print 'Could not read 0x%x bytes at 0x%x' % (size, addr)
			return

		maddr = addr + size
		if maddr > 0x0000FFFFFFFFFFFF:
			ads = 16
		elif maddr > 0x00000000FFFFFFFF:
			ads = 12
		elif maddr > 0x000000000000FFFF:
			ads = 8
		else:
			ads = 4

		for i in xrange(0, size, 16):
			print ('%%0%ix |' % ads) % (addr + i), 
			for j in xrange(16):
				if i + j < size:
					print '%02x' % ord(data[i + j]), 
				else:
					print '  ', 
				if j == 7:
					print '', 
			print '|', 
			side = ''
			for j in xrange(min(16, size - i)):
				if 0x20 <= ord(data[i + j]) <= 0x7e:
					side += data[i+j]
				else:
					side += '.'
				if j == 7:
					side += ' '
			print side
		print ('%%0%ix' % ads) % size

	def do_disasm(self, line):
		try:
			addr, count = self.parseLine(line, (EXPR, EXPR), (None, 20))
		except ResolutionException, e:
			print e
			return
		offset = 0
		if addr is None and self.context is None:
			print 'No current thread context'
			return
		elif addr is None:
			addr, offset = self.context.pc, -10 * 4

		pc = self.context.pc if self.context is not None else None

		if addr & 3:
			print 'Address must be aligned'
			return
		data = self.dbg.readMemory(self.phandle, addr + offset, count * 4)
		if data is None and offset != 0:
			data = self.dbg.readMemory(self.phandle, addr, count * 4)
			offset = 0
		if data is None:
			print 'Could not read %i instructions at 0x%x' % (count, addr)
			return
		raddr = addr + offset

		insns = list(self.cs.disasm(data, raddr))
		maxmnemlen = max(len(insn.mnemonic) for insn in insns)
		for insn in insns:
			if insn.address == pc:
				print '-->', 
			else:
				print '   ', 
			print '0x%x' % insn.address, 
			print insn.mnemonic + ' ' * (maxmnemlen - len(insn.mnemonic)), 
			print insn.op_str

	def do_write(self, line):
		addr, data = self.parseLine(line, (EXPR, REST))
		data = ''.join(chr(int(ch, 16)) for ch in data.split(' '))
		self.dbg.writeMemory(self.phandle, addr, data)

	def do_stack(self, line):
		if self.context is None:
			print 'No current thread context'
			return

		cur = self.context.x29
		i = 0
		while cur != 0:
			data = self.dbg.readMemory(self.phandle, cur, 16)
			if data is None:
				break
			cur, lr = struct.unpack('<QQ', data)
			if lr == 0:
				break
			print '%i: 0x%x' % (i, lr)
			i += 1

	def dbgone(self):
		while True:
			try:
				evt = self.dbg.getDebugEvent(self.phandle)
				break
			except SwitchException:
				pass
			time.sleep(0.1)
		print evt
		if evt.tid != 0:
			self.context = self.dbg.getThreadContext(self.phandle, 15, evt.tid)
		else:
			self.context = None
		self.lastEvent = evt

def main():
	parser = argparse.ArgumentParser(description='CLI Debugger for Switch')
	parser.add_argument('--ip', default='10.0.0.217', help='IP to connect to (default 10.0.0.217)')
	parser.add_argument('--port', type=int, default=0xdead, help='Port to connect to (default 57005)')
	parser.add_argument('--titleid', default=None, help='Title ID to which the debugger attaches')
	parser.add_argument('--pid', type=int, default=-1, help='Process ID to which the debugger attaches')
	args = parser.parse_args()
	if args.pid != -1 and args.titleid is not None:
		print >>sys.stderr, 'Cannot specify both PID and title ID'
		return -1

	cmd = Clidbg(args.ip, args.port)
	if args.titleid is not None:
		cmd.do_attachtitle(args.titleid)
		cmd.do_break()
	elif args.pid != -1:
		cmd.do_attach(args.pid)
		cmd.do_break()
	while True:
		try:
			cmd.cmdloop()
		except KeyboardInterrupt:
			print

if __name__=='__main__':
	sys.exit(main())
