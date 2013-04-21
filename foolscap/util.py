
import socket
import time
from twisted.internet import address, defer, reactor, protocol


class AsyncAND(defer.Deferred):
    """Like DeferredList, but results are discarded and failures handled
    in a more convenient fashion.

    Create me with a list of Deferreds. I will fire my callback (with None)
    if and when all of my component Deferreds fire successfully. I will fire
    my errback when and if any of my component Deferreds errbacks, in which
    case I will absorb the failure. If a second Deferred errbacks, I will not
    absorb that failure.

    This means that you can put a bunch of Deferreds together into an
    AsyncAND and then forget about them. If all succeed, the AsyncAND will
    fire. If one fails, that Failure will be propagated to the AsyncAND. If
    multiple ones fail, the first Failure will go to the AsyncAND and the
    rest will be left unhandled (and therefore logged).
    """

    def __init__(self, deferredList):
        defer.Deferred.__init__(self)

        if not deferredList:
            self.callback(None)
            return

        self.remaining = len(deferredList)
        self._fired = False

        for d in deferredList:
            d.addCallbacks(self._cbDeferred, self._cbDeferred,
                           callbackArgs=(True,), errbackArgs=(False,))

    def _cbDeferred(self, result, succeeded):
        self.remaining -= 1
        if succeeded:
            if not self._fired and self.remaining == 0:
                # the last input has fired. We fire.
                self._fired = True
                self.callback(None)
                return
        else:
            if not self._fired:
                # the first Failure is carried into our output
                self._fired = True
                self.errback(result)
                return None
            else:
                # second and later Failures are not absorbed
                return result

# adapted from Tahoe: finds a single publically-visible address, or None.
# Tahoe also uses code to run /bin/ifconfig (or equivalent) to find other
# addresses, but that's a bit heavy for this. Note that this runs
# synchronously. Also note that this doesn't require the reactor to be
# running.
def get_local_ips_for(target='A.ROOT-SERVERS.NET'):
    """Find out what our IP address is for use by a given target.

    @return: the IP address as a dotted-quad string which could be used by
              to connect to us. It might work for them, it might not. If
              there is no suitable address (perhaps we don't currently have an
              externally-visible interface), this will return None.
    """
    try:
        target_ipaddr = socket.gethostbyname(target)
    except socket.gaierror:
        # DNS isn't running
        return None
    udpprot = protocol.DatagramProtocol()
    port = reactor.listenUDP(0, udpprot)
    try:
        udpprot.transport.connect(target_ipaddr, 7)
        localip = udpprot.transport.getHost().host
    except socket.error:
        # no route to that host
        localip = None
    port.stopListening() # note, this returns a Deferred
    return [localip]

def determineHostIPCapability():
    if hasattr(address, 'IPv6Address'):
        s = None
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.bind(('::1', 0))
            s.listen(1)
            ipv6_enabled = True
        except:
            ipv6_enabled = False
        if s: s.close()
    else:
        ipv6_enabled = False

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        ipv4_enabled = True
    except:
        ipv4_enabled = False
    if s: s.close()

    # I'm not sure if this is working, I need more machines without IPv6...
    if ipv6_enabled and ipv4_enabled:
        s4 = s6 = None
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.bind(('::', 0))
            s6.listen(1)
            s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s4.bind(('0.0.0.0', s6.getsockname()[1]))
            s4.listen(1)
            ip_dual_stack = False # if I listen on IPv6, I'm not listening on IPv4
        except:
            ip_dual_stack = True # if I listen on IPv6, I'm also listening on IPv4
        if s4: s4.close()
        if s6: s6.close()
    else:
        ip_dual_stack = False
    return (ipv4_enabled, ipv6_enabled, ip_dual_stack)

FORMAT_TIME_MODES = ["short-local", "long-local", "utc", "epoch"]
def format_time(when, mode):
    if mode == "short-local":
        time_s = time.strftime("%H:%M:%S", time.localtime(when))
        time_s = time_s + ".%03d" % int(1000*(when - int(when)))
    elif mode == "long-local":
        lt = time.localtime(when)
        time_s = time.strftime("%Y-%m-%d_%H:%M:%S", lt)
        time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
        time_s += time.strftime("%z", lt)
    elif mode == "utc":
        time_s = time.strftime("%Y-%m-%d_%H:%M:%S", time.gmtime(when))
        time_s = time_s + ".%06d" % int(1000000*(when - int(when)))
        time_s += "Z"
    elif mode == "epoch":
        time_s = "%.03f" % when
    return time_s
