# # -*- coding: utf-8 -*-
from __future__ import print_function

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto.ofproto_v1_4_parser import OFPActionPushVlan, OFPActionSetField
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

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

    def __init__(self, dpid, host_ip, type):
        self.dpid = dpid
        self.type = type  # Either VXLAN_GATEWAY or VXLAN_ENABLED
        self.host_ip = host_ip
        self.vni_to_local_port = {}  # (VNI -> local_ports)
        self.vni_to_vxlan_port = {}  # (VNI -> vxlan_ports)
        self.vni_to_vlan = {}  # (VNI -> VLAN)
        self.vlanId_to_trunk_port = {}  # (vlanID -> trunk_ports)
        self.mac_vni_to_port = {}

    def __repr__(self):
        return "Switch: type= {0}, dpid= {1}, host_ip= {2}, vni_to_local_port={3}, vni_to_vxlan_port={4} vni_to_vlan={5}".format(
            self.type, hex(self.dpid), self.host_ip, self.vni_to_local_port, self.vni_to_vxlan_port, self.vni_to_vlan)


class VtepConfigurator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def _read_config(self, file_name="CONFIG.json"):
        with open(file_name) as config:
            config_data = json.load(config)

        # for server_ip, vnis in config_data['IP_VNI'].items():
        #     self.ip_vni[server_ip] = map(int, vnis.split(','))

        for dp in config_data['switches']:
            switch_type = VXLAN_ENABLED if dp[
                'type'] == 'VXLAN_ENABLED' else VXLAN_GATEWAY
            dpid = int(dp['id'], 16)
            host_ip = dp['host_ip']
            switch = Switch(dpid=dpid, host_ip=host_ip, type=switch_type)
            if switch_type == VXLAN_ENABLED:
                for vni, ports in dp["vni_to_local_and_vxlan_port"].items():
                    local_ports, vxlan_ports = ports
                    switch.vni_to_local_port.update(
                        {int(vni): map(int, local_ports.split(','))})
                    switch.vni_to_vxlan_port.update(
                        {int(vni): map(int, vxlan_ports.split(','))})
            else:
                for vni, values in dp["vni_to_vlan_and_vxlan_port"].items():
                    vlanID, vxlan_ports = values
                    switch.vni_to_vlan.update(
                        {int(vni): map(int, vlanID.split(','))[0]})
                    switch.vni_to_vxlan_port.update(
                        {int(vni): map(int, vxlan_ports.split(','))})
                # pdb.set_trace()
                switch.vlanId_to_trunk_port = {int(vlanID): map(
                    int, ports) for vlanID, ports in dp['vlan_to_trunk_port'].items()}
            self.switches[dpid] = switch
        print (switch)

    def __init__(self, *args, **kwargs):
        super(VtepConfigurator, self).__init__(*args, **kwargs)
        # data-paths that are being controlled by this controller.
        self.switches = {}
        # self.mac_vni_to_hostip = {}  # (mac, vni) -> hostIP
        self._read_config(file_name="CONFIG.json")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _connection_up_handler(self, ev):
        def _add_default_resubmit_rule(next_table_id=1):
            # Adds a low priority rule in table 0 to resubmit the unmatched packets
            # (i.e. the packets which didn't come from local port) to table 1
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(next_table_id)]
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("{0} : {1} : Rule added, table={2} priority={3} resubmit={4}".format(
                dpid_hex, st, 0, 0, next_table_id))

            # Add a low priority rule in table 1 to forward table-miss to controller.
            # These will cause a Packet_IN at controller
            actions = [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("{0} : {1} : Rule added, table={2} priority={3} Forward to COTROLLER".format(
                dpid_hex, st, 1, 0))

        datapath = ev.msg.datapath
        dpid = datapath.id
        dpid_hex = hex(dpid)

        if dpid not in self.switches:  # if the dpid was not specified in CONFIG file
            raise VtepConfiguratorException(dpid)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Forward all other packets to table 1 in packet processing pipeline.
        _add_default_resubmit_rule(next_table_id=1)

        # Switch will conatin all the information from CONFIG about this
        # particular datapath
        switch = self.switches[dpid]
        if switch.type == VXLAN_ENABLED:
            # (e.g. vni=101 and ports= [1,4])
            for vni, ports in switch.vni_to_local_port.items():
                for port in ports:
                    # table=0, in_port=<1>,actions=set_field:<100>->tun_id,resubmit(,1)
                    # These rules will ensure that all the packets coming from local ports
                    # have tunnel_id associated with them, when packet
                    # processing reaches table 1.
                    match = parser.OFPMatch(in_port=port)
                    actions = [parser.NXActionSetTunnel(tun_id=vni)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(1)]  # resubmit(,1)
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst)
                    st = datapath.send_msg(mod)
                    print ("{0} : {1} : Rule added, match(in_port={2}) set_tun_id={3}, resubmit({4}".format(
                        dpid_hex, st, port, vni, 1))

        elif switch.type == VXLAN_GATEWAY:
            for vni, vlan in switch.vni_to_vlan.items():
                # Add a rule to stip VLAN ID, Add a corresponding VNI and resubmit to 1
                # These rules will ensure that all the packets coming from local ports
                # have VLAN tag stripped off and corresponding tun_id
                # assiciated
                # vlan is a list with just one item
                match = parser.OFPMatch(vlan_vid=(0x1000 | vlan))
                actions = [parser.OFPActionPopVlan(
                ), parser.NXActionSetTunnel(tun_id=vni)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(1)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                        match=match, instructions=inst)
                st = datapath.send_msg(mod)
                print("{0}: {1}: Rule Added, match(vlan={2}) pop_vlan, set_tun_id={3} resubmit={4}".format(
                    dpid_hex, st, vlan, vni, 1))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        dpid_hex = hex(dpid)
        if dpid not in self.switches:
            raise VtepConfiguratorException(dpid)
        switch = self.switches[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # ignore LLDP packet

        in_port = msg.match['in_port']
        # Only those packets will come to controller which have tunnel_id
        # already set.
        vni = msg.match['tunnel_id']
        print ("{0} Received a packet on port={1} of VNI ID={2} from eth_src={3} to eth_dst={4}".format(
            dpid_hex, in_port, vni, eth.src, eth.dst))

        # Save the (src_mac, VNI) -> port mapping in switch
        switch.mac_vni_to_port[(eth.src, vni)] = in_port
        vxlan_ports = switch.vni_to_vxlan_port[vni][:]  # Deep copy

        if switch.type == VXLAN_ENABLED:

            if eth.dst == L2_BROADCAST:
                # If a broadcast packet has been received from a VXLAN tunnel port then
                # multicast it on local ports.
                local_ports = switch.vni_to_local_port[vni][:]
                if in_port in vxlan_ports:  # Incoming traffic
                    for port in local_ports:  # Multicast on each local ports
                        actions = [parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print("{0}: {1} Packet src={2}, destination={3}, output={4}".format(
                            dpid_hex, st, eth.src, eth.dst, port))
                else:  # Coming from local port, output on all VXLAN port and local port on the same VNI
                    local_ports.remove(in_port)
                    for port in local_ports:  # Forward on other local ports of the same VNI
                        actions = [parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print("{0}: {1} Packet src={2}, destination={3}, output={4}".format(dpid_hex, st, eth.src,
                                                                                            eth.dst, port))
                    for port in vxlan_ports:  # Multicast on all subscriber VXLAN ports.
                        # Set tunnel ID and output on the VXLAN ports
                        actions = [parser.NXActionSetTunnel(
                            tun_id=vni), parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print("{0} : {1} Packet output in_port={2} setTunnelId={3} out_port={4}".format(
                            dpid, st, in_port, vni, port))

            else:  # Unicast message
                if in_port in vxlan_ports:  # Incoming unicast message
                    try:
                        out_port = switch.mac_vni_to_port[(eth.dst, vni)]
                    except KeyError as e:
                        print(e)
                    # Add a rule for packets from VXLAN_port to local_port
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.dst)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0} : {1} Rule added. match(tun_id={2}, eth.dst={3}). Output(port={4})".format(
                        dpid_hex, st, vni, eth.dst, out_port))

                    # Add rule for packets from VXLAN_port to local_port
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    actions = [parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0} : {1} Rule added. match(tun_id={2}, eth.dst={3}). Output(port={4})".format(
                        dpid_hex, st, vni, eth.src, in_port))

                    # Output the packet
                    actions = [parser.OFPActionOutput(port=out_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                              actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print("{0} : {1} Outgoing traffic. setTunnelId={2} out_port={3}".format(
                        dpid_hex, st, vni, out_port))

                else:  # Outgoing unicast message
                    try:
                        out_port = switch.mac_vni_to_port[(eth.dst, vni)]
                    except KeyError as e:
                        print(e)
                    # Add rule for packets from local_ports to VXLAN_ports
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.dst)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0} : {1} Rule added. match(tun_id={2}, eth.dst={3}). Output(port={4})".format(
                        dpid_hex, st, vni, eth.dst, out_port))

                    # Add rule for packets from VXLAN_port to local_port
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    actions = [parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0} : {1} Rule added. match(tun_id={2}, eth.dst={3}). Output(port={4})".format(
                        dpid_hex, st, vni, eth.src, out_port))

                    # Output the packet on out_port
                    actions = [parser.NXActionSetTunnel(
                        tun_id=vni), parser.OFPActionOutput(port=out_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                              actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print("{0} : {1} Outgoing traffic. setTunnelId={2} out_port={3}".format(
                        dpid_hex, st, vni, out_port))

        if switch.type == VXLAN_GATEWAY:
            vlan_id = switch.vni_to_vlan[vni]
            #vxlan_ports = switch.vni_to_vxlan_port[vni][:]
            if eth.dst == L2_BROADCAST:

                if in_port in vxlan_ports:  # Incoming traffic

                    trunk_ports = switch.vlanId_to_trunk_port[vlan_id]
                    for port in trunk_ports:  # Output on all ports that are on VLAN networks
                        actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                                   OFPActionSetField(
                                       vlan_vid=(0x1000 | vlan_id)),
                                   parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print("{0}: {1} Packet out. Actions=Set_VLAN_id={2}, out_port={3}".format(
                            dpid_hex, st, vlan_id, port))
                else:  # Outgoing traffic
                    for port in vxlan_ports:
                        actions = [parser.NXActionSetTunnel(
                            tun_id=vni), parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print("{0}: {1} Outgoing traffic output. setTunnelID={2} out_port={3}".format(
                            dpid_hex, st, vni, port))

            else:  # Unicast message

                if in_port in vxlan_ports:  # Incoming traffic
                    try:
                        out_port = switch.mac_vni_to_port[(eth.dst, vni)]
                    except KeyError as e:
                        print(e)
                    # Add rule for forwarding from trunk_ports to VXLAN_ports
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    actions = [parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print(
                        "{0} : {1} Rule added table=1, priority=100, match(tunnel_id={2}, eth_dst={3}, out_port={4}".format(
                            dpid_hex, st, vni, eth.src, in_port))

                    # Add rule for forwarding from VXLAN_ports to trunk_ports
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.dst)
                    actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q), OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                               parser.OFPActionOutput(port=out_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0}: {1} Rule Added. match(tun_id={2}, eth_dst={3}), Action(VLAN_id={4}, output={5})".format(
                        dpid_hex, st, vni, eth.dst, vlan_id, out_port))

                    # Actually output the packet
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                              actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print("{0}: {1} Packet Output. SetVlanID:{2} output={3}".format(
                        dpid_hex, st, vlan_id, out_port))

                else:  # outgoing traffic
                    try:
                        out_port = switch.mac_vni_to_port[(eth.dst, vni)]
                    except KeyError as e:
                        print(e)
                    # Add a unicast rule for traffic forward from trunk_port to
                    # vxlan_port
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.dst)
                    actions = [parser.OFPActionOutput(port=out_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0} : {1} Rule added table=1, priority=100, match(tunnel_id={2}, eth_dst={3}, out_port={4}".format(
                        dpid_hex, st, vni, eth.src, out_port))
                    # Add a unicast rule for traffic forward from vxlan_port to
                    # trunk_port
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                               OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                               parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print("{0}: {1} Rule Added. match(tun_id={2}, eth_dst={3}), Action(VLAN_id={4}, output={5})".format(
                        dpid_hex, st, vni, eth.dst, vlan_id, in_port))

                    # Actually output the packet.
                    actions = [parser.NXActionSetTunnel(
                        tun_id=vni), parser.OFPActionOutput(port=out_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                              actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print("{0}: {1} Packet out. Set tun_id={2} out_put_port={3}".format(
                        dpid_hex, st, vni, out_port))
