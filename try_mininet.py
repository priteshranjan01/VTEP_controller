from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."

    def build(self, n=2):
        print("line 13")
        ls = self.addSwitch('s1')
        rs = self.addSwitch('s2')
        for h in ['h1','h2']:
            host = self.addHost(h)
            self.addLink(host, ls)
        
        for h in ['h4','h5']:
            host = self.addHost(h)
            self.addLink(host, rs)
        self.addLink(ls, rs)

        #for h in ['h1','h2','h3','h4', 'h5']:
        #    host = self.addHost(h)
        #    self.addLink(host, ls)
        # ms = self.addSwitch('s2')
        # print("line 16")
        # # Python's range(N) generates 0..N-1
        # for h in ['h1', 'h2']:
        #     host = self.addHost(h)
        #     self.addLink(host, ls)
        # for h in ['h3', 'h4']:
        #     host = self.addHost(h)
        #     self.addLink(host, rs)
        # self.addLink(rs, ms)
        # self.addLink(ls, ms)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=4)
    net = Mininet(topo, controller=None)
    # h1 = net.get('h1')
    # h1.setMAC('00:00:00:00:00:00:01')
    #
    # h2 = net.get('h2')
    # h2.setMAC('00:00:00:00:00:00:02')
    #
    # h3 = net.get('h3')
    # h3.setMAC('00:00:00:00:00:00:03')
    #
    # h4 = net.get('h4')
    # h4.setMAC('00:00:00:00:00:00:04')


    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    #net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
        # Tell mininet to print useful information
        setLogLevel('info')
        simpleTest()