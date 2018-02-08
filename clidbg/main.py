from cmd import Cmd
import argparse, sys
try:
	try:
		import gnureadline as readline
	except ImportError:
		import readline
except ImportError:
	pass

from connection import Connection

class Clidbg(Cmd):
	def __init__(self, ip, port):
		Cmd.__init__(self)

		self.dbg = Connection(ip, port)

	def print_topics(self, header, cmds, cmdlen, maxcol):
		nix = 'EOF', 
		if header is not None:
			Cmd.print_topics(self, header, [cmd for cmd in cmds if cmd not in nix], cmdlen, maxcol)

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

	def do_exit(self, line):
		"""exit
		Exit the debugger."""
		print line
		sys.exit()

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
	elif args.pid != -1:
		cmd.do_attach(args.pid)
	while True:
		try:
			cmd.cmdloop()
		except KeyboardInterrupt:
			print

if __name__=='__main__':
	sys.exit(main())
