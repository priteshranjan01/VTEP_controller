# # -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

import pdb
import json

VXLAN_GATEWAY = 1
VXLAN_ENABLED = 2
L2_BROADCAST = 'ff:ff:ff:ff:ff:ff'
# TODO: Add log messages instead of print statements


class VtepConfiguratorException(Exception):
    def __init__(self, dpid):
        super(VtepConfiguratorException, self).__init__(
            "DPID {0} was not specified in configuration file".format(dpid)
        )


class Switch(object):
    def __init__(self, dpid, host_ip, mapping=None, type=VXLAN_ENABLED):
        self.dpid = dpid
        self.type = type  # Either VXLAN_GATEWAY or VXLAN_ENABLED
        self.mapping = mapping  # (VNI -> VLAN) or (VNI -> ports)
        self.host_ip = host_ip
        # self.mac_to_port = {}  # (mac, tun_id) -> port
        # TODO: generate this mapping dynamically
        self.vni_OFport = {101: [10],
                           102: [11],
                           103: [12]}  # local OF ports which reach the vni

    def __repr__(self):
        return "Switch: type= {0}, dpid= {1}, host_ip= {2}, mapping= {3}".format(self.type, self.dpid, self.host_ip, self.mapping)


class VtepConfigurator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def _read_config(self, file_name="CONFIG.json"):
        with open(file_name) as config:
            config_data = json.load(config)

        for server_ip, vnis in config_data['IP_VNI'].items():
            self.ip_vni[server_ip] = map(int, vnis.split(','))

        for dp in config_data['switches']:
            new_mapping = {}
            for vni, values in dp['mapping'].items():
                new_mapping[int(vni)] = map(int, dp['mapping'][vni].split(','))

            switch_type = VXLAN_ENABLED if dp['type'] == 'VXLAN_ENABLED' else VXLAN_GATEWAY
            print(new_mapping)

            dpid = int(dp['id'], 16)
            print (config_data)
            self.switches[dpid] = Switch(dpid=dpid, host_ip=dp['host_ip'], type=switch_type, mapping=new_mapping)

    def __init__(self, *args, **kwargs):
        super(VtepConfigurator, self).__init__(*args, **kwargs)
        self.switches = {} # data-paths that are being controlled by this controller.
        self.ip_vni = {}  # Server IP address -> subscribed VNIs
        self._read_config(file_name="CONFIG.json")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _connection_up_handler(self, ev):
        def _add_default_resubmit_rule(next_table_id=1):
            # Adds a low priority rule in table 0 to resubmit the unmatched packets to table 1
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(next_table_id)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("Rule added {0}, table={3} priority={1} resubmit={2}".format(st, 0, next_table_id, 0))

            # Add a low priority rule in table 1 to forward table-miss to controller
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("Rule added {0}, table={2} priority={1} Forward to COTROLLER".format(st, 0, next_table_id))

        datapath = ev.msg.datapath
        dpid = datapath.id

        if dpid not in self.switches:  # if the dpid was not specified in CONFIG file
            pdb.set_trace()
            raise VtepConfiguratorException(dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        _add_default_resubmit_rule(next_table_id=1)  # All other packets should be submitted to 1

        switch = self.switches[dpid]
        if switch.type == VXLAN_ENABLED:
            for vni, ports in switch.mapping.items():
                for port in ports:
                    # table=0, in_port=<1>,actions=set_field:<100>->tun_id,resubmit(,1)
                    match = parser.OFPMatch(in_port=port)
                    actions = [parser.NXActionSetTunnel(tun_id=vni)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(1)]  # resubmit(,1)
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst)
                    st = datapath.send_msg(mod)
                    print ("Rule added {0}: match(in_port={1}) set_tun_id={2}, resubmit({3}".format(st, port, vni, 1))

        elif switch.type == VXLAN_GATEWAY:
            for vni, vlan in switch.mapping.items():
                # Add a rule to stip VLAN ID, Add a corresponding VNI and resubmit to 1
                match = parser.OFPMatch(vlan_vid=(0x1000 | vlan[0]))  # vlan is a list with just one item
                actions = [parser.OFPActionPopVlan(), parser.NXActionSetTunnel(tun_id=vni)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(1)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                        match=match, instructions=inst)
                st = datapath.send_msg(mod)
                print("Rule Added {0}: match(vlan={1}) pop_vlan, set_tun_id={2} resubmit={3}".format(st, vlan[0], vni, 1))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # TODO: Keep timeouts for flow-mods that are in PACKET_IN handler
        msg = ev.msg
        datapath = msg.datapath
        if datapath.id not in self.switches:
            raise VtepConfiguratorException(datapath.id)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return  # ignore lldp packet

        in_port = msg.match['in_port']
        try:
            vni = msg.match['tunnel_id']
        except KeyError as e:
            print(e)
            pdb.set_trace()
            return

        # Learn the source's (MAC address, VNI) and Port mapping
        match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
        actions = [parser.OFPActionOutput(port=in_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                instructions=inst)
        st = datapath.send_msg(mod)
        print ("Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_dst={2}, out_port={3}".format(
            st, vni, eth.src, in_port))

        if eth.dst == L2_BROADCAST:
            # Output the packet at each of the local ports on server of this VNI and
            # to the VXLAN tunnel ports subscribed for this VNI

            # Learn the source's (IP address, VNI) and port mapping
            arp_pkt = pkt.get_protocol(arp.arp)  # TODO: There has to be a better way
            if arp_pkt is None:
                print ("A broadcast packet but not an ARP packet")
                return

            # This learning can be done from unicast packets also.
            src_ip = arp_pkt.src_ip
            match = parser.OFPMatch(tunnel_id=vni, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)
            actions = [parser.OFPActionOutput(port=in_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print ("Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_type={2}, ipv4_dst={3}".format(
                st, vni, ether_types.ETH_TYPE_IP, src_ip))

            switch = self.switches[datapath.id]
            vxlan_ports = switch.vni_OFport[vni][:]
            local_ports = switch.mapping[vni][:]
            if in_port in vxlan_ports:
                output_ports = local_ports  # Multi-cast on all local ports
            else:
                output_ports = vxlan_ports + local_ports.remove(in_port)
                # Multi-cast on all subscriber VXLAN_ports and local ports except the in_port
            print("output_ports = {0}".format(output_ports))
            for port in output_ports:
                actions = [parser.OFPActionOutput(port=port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=msg.data)
                st = datapath.send_msg(out)
                print ("Packet output {0} port={1}".format(st, port))
