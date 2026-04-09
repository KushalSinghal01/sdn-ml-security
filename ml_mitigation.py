from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer
import pickle
import pandas as pd
import numpy as np
import os
import time

log = core.getLogger()

MODEL_PATH = os.path.expanduser('~/Desktop/sdn_project/sdn_rf_model.pkl')

SYN_RATE_THRESHOLD  = 500
UDP_RATE_THRESHOLD  = 500
ICMP_RATE_THRESHOLD = 200
HTTP_RATE_THRESHOLD = 300

class MLMitigation(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.blocked_ips = set()
        self.notified_ips = set()
        self.connections = []
        self.packet_count = {}
        self.packet_time = {}
        self.syn_count = {}
        self.syn_time = {}
        self.mac_to_port = {}

        log.info("=" * 50)
        log.info("  ML Based SDN Mitigation Module ACTIVE")
        log.info("=" * 50)
        log.info("  Detecting: SYN | UDP | ICMP | HTTP Floods")
        log.info("  Smart blocking: Only attacker, not victim!")
        log.info("  Dashboard: http://127.0.0.1:5000")
        log.info("=" * 50)

        try:
            with open(MODEL_PATH, 'rb') as f:
                self.model_data = pickle.load(f)
            log.info("  ML Model loaded successfully!")
        except Exception as e:
            log.error(f"  Model load failed: {e}")
            self.model_data = None

        Timer(5, self._request_stats, recurring=True)
        Timer(3, self._check_pending_unblocks, recurring=True)

    def _request_stats(self):
        for con in self.connections:
            try:
                con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
            except Exception as e:
                log.warning("Could not request stats: %s" % e)

    def _check_pending_unblocks(self):
        try:
            import urllib.request
            import json
            req = urllib.request.Request('http://127.0.0.1:5000/api/pending_unblocks')
            res = urllib.request.urlopen(req, timeout=2)
            result = json.loads(res.read())
            for ip in result.get('pending', []):
                self._do_unblock(ip)
        except Exception as e:
            log.debug("Unblock check failed: %s" % e)

    def _do_unblock(self, ip):
        log.warning("*** UNBLOCKING IP: %s ***" % ip)
        self.blocked_ips.discard(ip)
        self.notified_ips.discard(ip)

        # Rate counters reset karo
        if ip in self.packet_count:
            del self.packet_count[ip]
        if ip in self.packet_time:
            del self.packet_time[ip]
        if ip in self.syn_count:
            del self.syn_count[ip]
        if ip in self.syn_time:
            del self.syn_time[ip]

        for con in self.connections:
            try:
                # Block rule delete karo
                msg = of.ofp_flow_mod()
                msg.command = of.OFPFC_DELETE
                msg.match.dl_type = 0x0800
                msg.match.nw_src = IPAddr(ip)
                msg.priority = 65535
                con.send(msg)
                log.warning("  Block rule removed for %s!" % ip)

                # Sab flow rules flush karo — fresh learning hogi
                msg2 = of.ofp_flow_mod()
                msg2.command = of.OFPFC_DELETE
                msg2.match = of.ofp_match()
                con.send(msg2)
                log.warning("  All flows flushed — fresh learning!")

            except Exception as e:
                log.warning("  Could not remove rule: %s" % e)

        # Poora MAC table reset karo
        self.mac_to_port = {}
        log.warning("  MAC table fully reset!")

        try:
            import urllib.request
            import json
            data = json.dumps({'ip': ip}).encode('utf-8')
            req = urllib.request.Request(
                'http://127.0.0.1:5000/api/confirm_unblock',
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=2)
            log.warning("  Unblock confirmed to dashboard!")
        except Exception as e:
            log.debug("Confirm unblock failed: %s" % e)

    def _handle_ConnectionUp(self, event):
        log.info("Switch connected: %s" % event.dpid)
        self.connections.append(event.connection)
        self.mac_to_port[event.dpid] = {}

    def _handle_ConnectionDown(self, event):
        if event.connection in self.connections:
            self.connections.remove(event.connection)
            log.info("Switch disconnected: %s" % event.dpid)

    def _handle_FlowStatsReceived(self, event):
        if not self.model_data:
            return
        for stat in event.stats:
            try:
                src = str(stat.match.nw_src) if stat.match.nw_src else '0.0.0.0'
                dst = str(stat.match.nw_dst) if stat.match.nw_dst else '0.0.0.0'
                proto = stat.match.nw_proto if stat.match.nw_proto else 0

                if src in self.blocked_ips or src == '0.0.0.0':
                    continue

                # ICMP reply — victim response skip karo
                if proto == 1 and dst in self.blocked_ips:
                    continue

                # UDP response — victim skip karo
                if proto == 17 and dst in self.blocked_ips:
                    continue

                proto_name = 'UDP' if proto == 17 else 'TCP' if proto == 6 else 'ICMP'
                traffic = {
                    'switch': event.connection.dpid,
                    'src': src, 'dst': dst,
                    'pktcount': stat.packet_count,
                    'bytecount': stat.byte_count,
                    'dur': stat.duration_sec,
                    'dur_nsec': stat.duration_nsec,
                    'tot_dur': stat.duration_sec * 1e9 + stat.duration_nsec,
                    'flows': 1,
                    'packetins': stat.packet_count,
                    'pktperflow': stat.packet_count,
                    'byteperflow': stat.byte_count,
                    'pktrate': stat.packet_count / max(stat.duration_sec, 1),
                    'Pairflow': 0, 'Protocol': proto_name,
                    'port_no': stat.match.tp_dst if stat.match.tp_dst else 0,
                    'tx_bytes': stat.byte_count,
                    'rx_bytes': stat.byte_count // 2,
                    'tx_kbps': 0, 'rx_kbps': 0, 'tot_kbps': 0
                }
                pkt_rate = traffic['pktrate']
                prediction, confidence = self._predict(traffic)
                if prediction == 1 and confidence > 0.5:
                    log.warning("*** ML ATTACK DETECTED: %s ***" % src)
                    self._block_ip(event.connection, src, proto_name + ' FLOOD', pkt_rate)
                else:
                    log.debug("Flow OK: %s (pred=%s, conf=%.2f, rate=%.1f)" % (src, prediction, confidence, pkt_rate))
            except Exception as e:
                log.warning("Stat error: %s" % e)

    def _predict(self, traffic):
        try:
            model = self.model_data['model']
            features = self.model_data['features']
            le_src = self.model_data['le_src']
            le_dst = self.model_data['le_dst']
            le_proto = self.model_data['le_proto']
            df = pd.DataFrame([traffic])
            df['src'] = le_src.transform([str(traffic['src'])])[0] if str(traffic['src']) in le_src.classes_ else 0
            df['dst'] = le_dst.transform([str(traffic['dst'])])[0] if str(traffic['dst']) in le_dst.classes_ else 0
            df['Protocol'] = le_proto.transform([str(traffic['Protocol'])])[0] if str(traffic['Protocol']) in le_proto.classes_ else 0
            X = df[features]
            pred = model.predict(X)[0]
            conf = model.predict_proba(X)[0][pred]
            return pred, conf
        except Exception as e:
            log.warning("Prediction error: %s" % e)
            return 0, 0

    def _block_ip(self, connection, ip, attack_type='SYN FLOOD', rate=0):
        if ip in self.blocked_ips:
            return
        self.blocked_ips.add(ip)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800
        msg.match.nw_src = IPAddr(ip)
        msg.priority = 65535
        msg.actions = []
        connection.send(msg)
        log.warning("*** BLOCK RULE INSTALLED: %s ***" % ip)
        self._notify_dashboard(ip, attack_type, rate)

    def _notify_dashboard(self, ip, attack_type, rate):
        if ip in self.notified_ips:
            return
        self.notified_ips.add(ip)
        try:
            import urllib.request
            import json
            data = json.dumps({
                'src': ip,
                'type': attack_type,
                'rate': round(rate),
                'reason': '%s — %s pkts/sec' % (attack_type, round(rate))
            }).encode('utf-8')
            req = urllib.request.Request(
                'http://127.0.0.1:5000/api/attack',
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=2)
            log.info("Dashboard notified!")
        except Exception as e:
            log.debug("Dashboard notify failed: %s" % e)

    def _handle_PacketIn(self, event):
        try:
            from pox.lib.packet import ethernet, ipv4, tcp, udp, icmp
            pkt = event.parsed
            if not pkt:
                return
            dpid = event.connection.dpid
            in_port = event.port
            if dpid not in self.mac_to_port:
                self.mac_to_port[dpid] = {}
            self.mac_to_port[dpid][pkt.src] = in_port
            ip = pkt.find('ipv4')
            if not ip:
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                event.connection.send(msg)
                return
            src_ip = str(ip.srcip)
            if src_ip in self.blocked_ips:
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x0800
                msg.match.nw_src = IPAddr(src_ip)
                msg.priority = 65535
                msg.actions = []
                event.connection.send(msg)
                return
            now = time.time()
            tcp_pkt  = pkt.find('tcp')
            udp_pkt  = pkt.find('udp')
            icmp_pkt = pkt.find('icmp')

            if tcp_pkt and tcp_pkt.SYN and not tcp_pkt.ACK:
                self._rate_check(event, src_ip, self.syn_count, self.syn_time,
                                 SYN_RATE_THRESHOLD, "SYN FLOOD", now)
            elif udp_pkt and udp_pkt.dstport < 1024:
                self._rate_check(event, src_ip, self.packet_count, self.packet_time,
                                 UDP_RATE_THRESHOLD, "UDP FLOOD", now)
            elif icmp_pkt and icmp_pkt.type == 8:
                self._rate_check(event, src_ip, self.packet_count, self.packet_time,
                                 ICMP_RATE_THRESHOLD, "ICMP FLOOD", now)
            elif tcp_pkt and tcp_pkt.dstport == 80 and tcp_pkt.SYN:
                self._rate_check(event, src_ip, self.packet_count, self.packet_time,
                                 HTTP_RATE_THRESHOLD, "HTTP FLOOD", now)

            if pkt.dst in self.mac_to_port.get(dpid, {}):
                out_port = self.mac_to_port[dpid][pkt.dst]
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(pkt, in_port)
                msg.idle_timeout = 30
                msg.hard_timeout = 60
                msg.priority = 100
                msg.actions.append(of.ofp_action_output(port=out_port))
                msg.data = event.ofp
                event.connection.send(msg)
            else:
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                event.connection.send(msg)
        except Exception as e:
            log.debug("PacketIn error: %s" % e)

    def _rate_check(self, event, src_ip, count_dict, time_dict, threshold, attack_name, now):
        if src_ip not in time_dict:
            time_dict[src_ip] = now
            count_dict[src_ip] = 1
        else:
            count_dict[src_ip] += 1
            elapsed = now - time_dict[src_ip]
            if elapsed >= 1.0:
                rate = count_dict[src_ip] / elapsed
                if rate > threshold:
                    log.warning("*** %s DETECTED: %s (%.1f pkts/sec) ***" % (attack_name, src_ip, rate))
                    self._block_ip(event.connection, src_ip, attack_name, rate)
                time_dict[src_ip] = now
                count_dict[src_ip] = 0


def launch():
    core.registerNew(MLMitigation)
    log.info("ML Mitigation module launched!")
