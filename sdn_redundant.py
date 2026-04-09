from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.link import TCLink
import time

class RedundantSDNTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1', ip='10.0.0.1/8')
        h2 = self.addHost('h2', ip='10.0.0.2/8')
        h3 = self.addHost('h3', ip='10.0.0.3/8')
        h4 = self.addHost('h4', ip='10.0.0.4/8')
        h5 = self.addHost('h5', ip='10.0.0.5/8')
        h6 = self.addHost('h6', ip='10.0.0.6/8')

        self.addLink(s1, s2, bw=1000, delay='1ms')
        self.addLink(s3, s4, bw=1000, delay='1ms')
        self.addLink(s1, s3, bw=1000, delay='1ms')
        self.addLink(s1, s4, bw=1000, delay='1ms')
        self.addLink(s2, s3, bw=1000, delay='1ms')
        self.addLink(s2, s4, bw=1000, delay='1ms')

        self.addLink(h1, s3, bw=100, delay='5ms')
        self.addLink(h2, s3, bw=100, delay='5ms')
        self.addLink(h3, s4, bw=100, delay='5ms')
        self.addLink(h4, s4, bw=100, delay='5ms')
        self.addLink(h5, s1, bw=100, delay='2ms')
        self.addLink(h6, s2, bw=100, delay='2ms')


def run():
    setLogLevel('info')
    topo = RedundantSDNTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        controller=None
    )

    net.addController('c1', controller=RemoteController,
                      ip='127.0.0.1', port=6633)
    net.addController('c2', controller=RemoteController,
                      ip='127.0.0.1', port=6634)

    net.start()

    for sw in net.switches:
        sw.cmd('ovs-vsctl set bridge %s stp_enable=true' % sw.name)

    time.sleep(15)

    print("\n==========================================")
    print("  Redundant SDN Topology")
    print("==========================================")
    print("C1 -> port 6633  |  C2 -> port 6634")
    print("Switches -> s1, s2, s3, s4")
    print("Hosts    -> h1, h2, h3, h4, h5, h6")
    print("==========================================")
    print("\nUseful commands:")
    print("  pingall                           -> test connectivity")
    print("  net                               -> show topology")
    print("  h5 hping3 -S --flood -p 80 h6    -> SYN flood")
    print("  h5 hping3 --icmp --flood h6       -> ICMP flood")
    print("  h5 hping3 --udp --flood -p 80 h6 -> UDP flood")
    print("  sh ovs-ofctl dump-flows s1        -> show flow rules")
    print("==========================================\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()
