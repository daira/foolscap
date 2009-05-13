
import sys, pickle, time
from twisted.python import usage
from foolscap.logging.log import format_message

class DumpOptions(usage.Options):
    stdout = sys.stdout
    stderr = sys.stderr
    synopsis = "Usage: flogtool dump DUMPFILE.pickle"
    optFlags = [
        ("verbose", "v", "Show all event arguments"),
        ("just-numbers", "n", "Show only event numbers"),
        ("rx-time", "r", "Show event receipt time (in addition to emit time)"),
        ]

    def parseArgs(self, dumpfile):
        self.dumpfile = dumpfile

class LogDumper:
    def __init__(self):
        self.trigger = None

    def run(self, options):
        self.options = options
        try:
            self.start()
        except IOError:
            sys.exit(1)

    def start(self):
        stdout = self.options.stdout
        for e in self.get_events():
            if "header" in e:
                h = e["header"]
                if h["type"] == "incident":
                    t = h["trigger"]
                    self.trigger = (t["incarnation"], t["num"])
                if self.options['verbose']:
                    print >>stdout, e
                if not self.options["just-numbers"] and not self.options["verbose"]:
                    if "versions" in h:
                        print >>stdout, "Application versions (embedded in logfile):"
                        versions = h["versions"]
                        longest = max([len(name) for name in versions] + [0])
                        fmt = "%" + str(longest) + "s: %s"
                        for name in sorted(versions.keys()):
                            print >>stdout, fmt % (name, versions[name])
                    if "pid" in h:
                        print >>stdout, "PID: %s" % (h["pid"],)
                    print >>stdout
            if "d" in e:
                self.print_event(e)

    def format_time(self, when):
        time_s = time.strftime("%H:%M:%S", time.localtime(when))
        time_s = time_s + ".%03d" % int(1000*(when - int(when)))
        return time_s

    def print_event(self, e):
        short = e['from'][:8]
        d = e['d']
        when = self.format_time(d['time'])
        if self.options['just-numbers']:
            print >>self.options.stdout, when, d.get('num')
            return

        eid = (d["incarnation"], d["num"])
        # let's mark the trigger event from incident reports with
        # [INCIDENT-TRIGGER] at the end of the line
        is_trigger = bool(self.trigger and (eid == self.trigger))
        text = format_message(d)

        t = "%s#%d " % (short, d['num'])
        if self.options['rx-time']:
            rx_when = self.format_time(e['rx_time'])
            t += "rx(%s) " % rx_when
            t += "emit(%s)" % when
        else:
            t += "%s" % when
        t += ": %s" % text
        if self.options['verbose']:
            t += ": %r" % d
        if is_trigger:
            t += " [INCIDENT-TRIGGER]"
        print >>self.options.stdout, t
        if 'failure' in d:
            print >>self.options.stdout," FAILURE:"
            lines = str(d['failure']).split("\n")
            for line in lines:
                print >>self.options.stdout, " %s" % (line,)

    def get_events(self):
        fn = self.options.dumpfile
        if fn.endswith(".bz2"):
            import bz2
            f = bz2.BZ2File(fn, "r")
        else:
            f = open(fn, "rb")
        while True:
            try:
                e = pickle.load(f)
                yield e
            except EOFError:
                break

