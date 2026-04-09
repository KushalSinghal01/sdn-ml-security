from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.link import TCLink

class HybridMeshTreeTopo(Topo):
    """
    Hybrid Mesh-Tree SDN Topology
    
    Architecture:
    - 4 Controllers (C1, C2, C3, C4) — all equal, load sharing
    - 5 Switches (S1-S5) — hybrid connected
    - 18 Hosts (h1-h18) — tree style under switches
    
    Controller → Switch mapping:
    C1 (6633) → S1, S2
    C2 (6634) → S1, S2, S3
    C3 (6635) → S3, S4, S5
    C4 (6636) → S4, S5
    
    Switch mesh:
    S1-S2, S2-S3, S3-S4, S4-S5, S1-S3, S2-S4, S1-S5 (linear + cross links)
    """
    def build(self):
        # 5 Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        # Switch mesh links
        self.addLink(s1, s2, bw=1000, delay='1ms')
        self.addLink(s2, s3, bw=1000, delay='1ms')
        self.addLink(s3, s4, bw=1000, delay='1ms')
        self.addLink(s4, s5, bw=1000, delay='1ms')
        # Cross links (mesh)
        self.addLink(s1, s3, bw=1000, delay='2ms')
        self.addLink(s2, s4, bw=1000, delay='2ms')
        self.addLink(s1, s5, bw=1000, delay='2ms')

        # Hosts under S1 (h1, h2, h3, h4)
        h1 = self.addHost('h1', ip='10.0.0.1/8')
        h2 = self.addHost('h2', ip='10.0.0.2/8')
        h3 = self.addHost('h3', ip='10.0.0.3/8')
        h4 = self.addHost('h4', ip='10.0.0.4/8')
        self.addLink(h1, s1, bw=100, delay='5ms')
        self.addLink(h2, s1, bw=100, delay='5ms')
        self.addLink(h3, s1, bw=100, delay='5ms')
        self.addLink(h4, s1, bw=100, delay='5ms')

        # Hosts under S2 (h5, h6, h7)
        h5 = self.addHost('h5', ip='10.0.0.5/8')
        h6 = self.addHost('h6', ip='10.0.0.6/8')
        h7 = self.addHost('h7', ip='10.0.0.7/8')
        self.addLink(h5, s2, bw=100, delay='5ms')
        self.addLink(h6, s2, bw=100, delay='5ms')
        self.addLink(h7, s2, bw=100, delay='5ms')

        # Hosts under S3 (h8, h9, h10, h11)
        h8  = self.addHost('h8',  ip='10.0.0.8/8')
        h9  = self.addHost('h9',  ip='10.0.0.9/8')
        h10 = self.addHost('h10', ip='10.0.0.10/8')
        h11 = self.addHost('h11', ip='10.0.0.11/8')
        self.addLink(h8,  s3, bw=100, delay='5ms')
        self.addLink(h9,  s3, bw=100, delay='5ms')
        self.addLink(h10, s3, bw=100, delay='5ms')
        self.addLink(h11, s3, bw=100, delay='5ms')

        # Hosts under S4 (h12, h13, h14)
        h12 = self.addHost('h12', ip='10.0.0.12/8')
        h13 = self.addHost('h13', ip='10.0.0.13/8')
        h14 = self.addHost('h14', ip='10.0.0.14/8')
        self.addLink(h12, s4, bw=100, delay='5ms')
        self.addLink(h13, s4, bw=100, delay='5ms')
        self.addLink(h14, s4, bw=100, delay='5ms')

        # Hosts under S5 (h15, h16, h17, h18)
        # Note: adjusted to 18 hosts total
        h15 = self.addHost('h15', ip='10.0.0.15/8')
        h16 = self.addHost('h16', ip='10.0.0.16/8')
        h17 = self.addHost('h17', ip='10.0.0.17/8')
        h18 = self.addHost('h18', ip='10.0.0.18/8')  
        self.addLink(h15, s5, bw=100, delay='5ms')
        self.addLink(h16, s5, bw=100, delay='5ms')
        self.addLink(h17, s5, bw=100, delay='5ms')
        self.addLink(h18, s5, bw=100, delay='2ms')


def run():
    setLogLevel('info')
    topo = HybridMeshTreeTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        controller=None
    )

    # 4 controllers 
    c1 = net.addController('c1', controller=RemoteController,
                           ip='127.0.0.1', port=6633)
    c2 = net.addController('c2', controller=RemoteController,
                           ip='127.0.0.1', port=6634)
    c3 = net.addController('c3', controller=RemoteController,
                           ip='127.0.0.1', port=6635)
    c4 = net.addController('c4', controller=RemoteController,
                           ip='127.0.0.1', port=6636)

    net.start()
    import time
    time.sleep(2)

    # STP enable karo loops se bachne ke liye
    for sw in net.switches:
        sw.cmd('ovs-vsctl set bridge %s stp_enable=true' % sw.name)
        sw.cmd('ovs-vsctl set bridge %s rstp_enable=true' % sw.name)
    
    time.sleep(15)  # STP settle hone do

    # Assign controllers to switches as per topology
    net['s1'].cmd('ovs-vsctl set-controller s1 '
              'tcp:127.0.0.1:6633 tcp:127.0.0.1:6634')
    net['s1'].cmd('ovs-vsctl set bridge s1 fail-mode=secure')

    net['s2'].cmd('ovs-vsctl set-controller s2 '
              'tcp:127.0.0.1:6633 tcp:127.0.0.1:6634')
    net['s2'].cmd('ovs-vsctl set bridge s2 fail-mode=secure')

    net['s3'].cmd('ovs-vsctl set-controller s3 '
              'tcp:127.0.0.1:6634 tcp:127.0.0.1:6635')
    net['s3'].cmd('ovs-vsctl set bridge s3 fail-mode=secure')

    net['s4'].cmd('ovs-vsctl set-controller s4 '
              'tcp:127.0.0.1:6635 tcp:127.0.0.1:6636')
    net['s4'].cmd('ovs-vsctl set bridge s4 fail-mode=secure')

    net['s5'].cmd('ovs-vsctl set-controller s5 '
              'tcp:127.0.0.1:6635 tcp:127.0.0.1:6636')
    net['s5'].cmd('ovs-vsctl set bridge s5 fail-mode=secure')
    print("\n==========================================")
    print("  Hybrid Mesh-Tree SDN Topology")
    print("==========================================")
    print("Controllers (all equal):")
    print("  C1 → port 6633  |  C2 → port 6634")
    print("  C3 → port 6635  |  C4 → port 6636")
    print("Switch-Controller mapping:")
    print("  S1: C1, C2  |  S2: C1, C2")
    print("  S3: C2, C3  |  S4: C3, C4  |  S5: C3, C4")
    print("Hosts:")
    print("  S1: h1-h4   |  S2: h5-h7")
    print("  S3: h8-h11  |  S4: h12-h14")
    print("  S5: h15-h18 |")
    print("==========================================")
    print("\nUseful commands:")
    print("  pingall                              -> test connectivity")
    print("  h18 hping3 -S --flood -p 80 10.0.0.8 -> SYN flood attack")
    print("  h18 hping3 --icmp --flood 10.0.0.8   -> ICMP flood")
    print("  h18 hping3 --udp --flood 10.0.0.8    -> UDP flood")
    print("  sh ovs-ofctl dump-flows s1            -> show flow rules")
    print("==========================================\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()
