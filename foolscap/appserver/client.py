
import os, sys
from StringIO import StringIO
from twisted.python import usage
from twisted.internet import defer

# does "flappserver start" need us to refrain from importing the reactor here?
import foolscap
from foolscap.api import Tub, Referenceable, fireEventually

class UploadOptions(usage.Options):
    #synopsis = "flappclient upload SOURCEFILE"
    def parseArgs(self, sourcefile):
        self.sourcefile = sourcefile

class Upload(Referenceable):
    def run(self, rref, options):
        name = os.path.basename(options.sourcefile)
        self.f = open(options.sourcefile, "rb")
        d = rref.callRemote("putfile", name, self)
        d.addCallback(self._done, options)
        return d

    def remote_read(self, size):
        return self.f.read(size)

    def _done(self, _ignored, options):
        print >>options.stdout, "File uploaded"
        return 0


class ExecOptions(usage.Options):
    pass

from twisted.internet.stdio import StandardIO
from twisted.internet.protocol import Protocol

class Exec(Referenceable, Protocol):
    def run(self, rref, options):
        self.done = False
        self.d = defer.Deferred()
        rref.notifyOnDisconnect(self._done, 3)
        self.buffered_stdin = []
        self.stdin_closed = False
        self.stdin_writer = None
        stdio = options.stdio
        stdio(self)
        self.stdout = options.stdout
        self.stderr = options.stderr
        d = rref.callRemote("execute", self)
        d.addCallback(self._started)
        d.addErrback(self._err)
        return self.d

    #def makeConnection(self):
    #    pass
    def dataReceived(self, data):
        # this is from stdin
        if self.stdin_writer is None:
            self.buffered_stdin.append(data)
        elif self.stdin_writer is False:
            pass # discard
        else:
            self.stdin_writer.callRemoteOnly("feed_stdin", data)

    def connectionLost(self, reason):
        self.stdin_closed = True
        if self.stdin_writer:
            self.stdin_writer.callRemoteOnly("close_stdin")

    def _started(self, stdin_writer):
        if stdin_writer:
            self.stdin_writer = stdin_writer # rref
            if self.buffered_stdin:
                self.stdin_writer.callRemoteOnly("feed_stdin",
                                                 "".join(self.buffered_stdin))
            if self.stdin_closed:
                self.stdin_writer.callRemoteOnly("close_stdin")
        else:
            # they don't want our stdin
            self.stdin_writer = False
        del self.buffered_stdin

    def remote_stdout(self, data):
        self.stdout.write(data)
        self.stdout.flush()
    def remote_stderr(self, data):
        self.stderr.write(data)
        self.stderr.flush()
    def remote_done(self, signal, exitcode):
        if signal:
            self._done(127)
        else:
            self._done(exitcode)
    def _err(self, f):
        self._done(f)
    def _done(self, res):
        if not self.done:
            self.done = True
            self.d.callback(res)

class ClientOptions(usage.Options):
    synopsis = "Usage: flappclient [--furl=|--furlfile=] (upload|exec)"

    optParameters = [
        ("furl", None, None, "FURL of the service to contact"),
        ("furlfile", "f", None, "file containing the FURL of the service"),
        ]

    subCommands = [
        ("upload", None, UploadOptions, "upload a file (to file-uploader)"),
        ("exec", None, ExecOptions, "cause a command to be run (to exec)"),
        ]

    def read_furlfile(self):
        for line in open(self["furlfile"]).readlines():
            line = line.strip()
            if line.startswith("pb://"):
                return line
        return None

    def postOptions(self):
        self.furl = self["furl"]
        if self["furlfile"]:
            self.furl = self.read_furlfile()
        if not self.furl:
            raise usage.UsageError("must provide --furl or --furlfile")
        if not hasattr(self, 'subOptions'):
            raise usage.UsageError("must specify a command")

    def opt_help(self):
        print >>self.stdout, self.synopsis
        sys.exit(0)

    def opt_version(self):
        from twisted import copyright
        print >>self.stdout, "Foolscap version:", foolscap.__version__
        print >>self.stdout, "Twisted version:", copyright.version
        sys.exit(0)

dispatch_table = {
    "upload": Upload,
    "exec": Exec,
    }

def run_cli(argv=None, run_by_human=True, stdio=StandardIO):
    if run_by_human:
        stdout = sys.stdout
        stderr = sys.stderr
    else:
        stdout = StringIO()
        stderr = StringIO()
    if argv:
        command_name,argv = argv[0],argv[1:]
    else:
        command_name = sys.argv[0]

    d = fireEventually()
    d.addCallback(lambda _ign: parse_options(command_name, argv,
                                             stdio, stdout, stderr))
    d.addCallback(run_command)

    if run_by_human:
        # we need to spin up our own reactor
        from twisted.internet import reactor
        stash_rc = []
        def good(rc):
            stash_rc.append(rc)
            reactor.stop()
        def oops(f):
            if f.check(SystemExit):
                stash_rc.append(f.value.args[0])
            else:
                print "Command failed:"
                print f
                stash_rc.append(-1)
            reactor.stop()
        d.addCallbacks(good, oops)
        reactor.run()
        sys.exit(stash_rc[0])
    else:
        def _convert_system_exit(f):
            f.trap(SystemExit)
            return f.value.args[0]
        d.addErrback(_convert_system_exit)
        def done(rc):
            return (rc, stdout.getvalue(), stderr.getvalue())
        d.addCallback(done)
        return d


def parse_options(command_name, argv, stdio, stdout, stderr):
    try:
        config = ClientOptions()
        config.stdout = stdout
        config.stderr = stderr
        config.parseOptions(argv)

        config.subOptions.stdio = stdio # for streaming input
        config.subOptions.stdout = stdout
        config.subOptions.stderr = stderr

    except usage.error, e:
        print >>stderr, "%s:  %s" % (command_name, e)
        print >>stderr
        c = getattr(config, 'subOptions', config)
        print >>stderr, str(c)
        sys.exit(1)

    return config

def run_command(config):
    c = dispatch_table[config.subCommand]()
    tub = Tub()
    d = defer.succeed(None)
    d.addCallback(lambda _ign: tub.startService())
    d.addCallback(lambda _ign: tub.getReference(config.furl))
    d.addCallback(c.run, config.subOptions) # might provide tub here
    d.addBoth(lambda res: tub.stopService().addCallback(lambda _ign: res))
    return d