# # -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto.ofproto_v1_4_parser import OFPActionPushVlan, OFPActionSetField
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4

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
        self.vni_OFport = {101: [10, 13],
                           102: [11, 14],
                           103: [12, 15]}  # local OF ports which reach the vni

        # This won't work
        self.vni_remoteip_to_ofport = {
            (101, '15.0.0.2'): 10,
            (101, '13.0.0.2'): 13,
            (101, '14.0.0.2'): 10
        }

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
        self.mac_vni_to_hostip = {}  # (mac, vni) -> hostIP
        self._read_config(file_name="CONFIG.json")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _connection_up_handler(self, ev):
        def _add_default_resubmit_rule(next_table_id=1):
            # Adds a low priority rule in table 0 to resubmit the unmatched packets to table 1
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(next_table_id)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("{4} Rule added {0}, table={3} priority={1} resubmit={2}".format(st, 0, next_table_id, 0, dpid))

            # Add a low priority rule in table 1 to forward table-miss to controller
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
            st = datapath.send_msg(mod)
            print("{3} Rule added {0}, table={2} priority={1} Forward to COTROLLER".format(st, 0, next_table_id, dpid))

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
                    print ("{4} Rule added {0}: match(in_port={1}) set_tun_id={2}, resubmit({3}".format(st, port, vni, 1, dpid))

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
                print("{4} Rule Added {0}: match(vlan={1}) pop_vlan, set_tun_id={2} resubmit={3}".format(st, vlan[0], vni, 1, dpid))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # TODO: Keep timeouts for flow-mods that are in PACKET_IN handler
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        if dpid not in self.switches:
            raise VtepConfiguratorException(dpid)
        switch = self.switches[dpid]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return  # ignore LLDP packet

        in_port = msg.match['in_port']
        try:
            vni = msg.match['tunnel_id']
        except KeyError as e:
            print e
            pdb.set_trace()
        print (in_port, vni)
        print ("packet", pkt)

        if switch.type == VXLAN_ENABLED:
            if eth.dst == L2_BROADCAST:
                # Learn the source's (MAC address, VNI) and Port mapping
                match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                self.mac_vni_to_hostip[(eth.src, vni)] = switch.host_ip
                actions = [parser.OFPActionOutput(port=in_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                        instructions=inst)
                st = datapath.send_msg(mod)
                print ("{4} Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_dst={2}, out_port={3}".format(
                    st, vni, eth.src, in_port, dpid))

                arp_pkt = pkt.get_protocol(arp.arp)  # TODO: There has to be a better way
                if arp_pkt is None:
                    print ("A broadcast packet but not an ARP packet")
                    return
                # Learn the source's (IP address, VNI) and port mapping
                # This learning can be done from unicast packets also.
                src_ip = arp_pkt.src_ip
                match = parser.OFPMatch(tunnel_id=vni, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)
                actions = [parser.OFPActionOutput(port=in_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)
                st = datapath.send_msg(mod)
                print ("{5} Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_type={2}, ipv4_dst={3} output={4}".format(
                    st, vni, ether_types.ETH_TYPE_IP, src_ip, in_port, dpid))

                # Output the packet at each of the local ports on server of this VNI and
                # to the VXLAN tunnel ports subscribed for this VNI
                vxlan_ports = switch.vni_OFport[vni][:]
                local_ports = switch.mapping[vni][:]
                if in_port in vxlan_ports:
                    #pdb.set_trace()
                    output_ports = local_ports  # Multi-cast on all local ports
                else:
                    local_ports.remove(in_port)
                    output_ports = vxlan_ports + local_ports
                    # Multi-cast on all subscriber VXLAN_ports and local ports except the in_port
                print("output_ports = {0}".format(output_ports))
                for port in output_ports:
                    actions = [parser.OFPActionOutput(port=port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print ("{2} Packet output {0} port={1} PKT=\n{3}".format(st, port, dpid, pkt))

            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if ipv4_pkt is not None:

                try:
                    remote_ip = self.mac_vni_to_hostip[(eth.dst, vni)]
                except KeyError:
                    print ("Ping from other side")  # Such a bad hack.
                    return
                out_ofport = switch.vni_remoteip_to_ofport[(vni, remote_ip)]
                print(eth.dst)
                #pdb.set_trace()
                match = parser.OFPMatch(tunnel_id=vni, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
                actions = [parser.OFPActionOutput(port=out_ofport)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)
                st = datapath.send_msg(mod)
                print ("{4} Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_type=IP, ipv4_dst={2} output={3}".format(
                    st, vni, ipv4_pkt.dst, out_ofport, dpid))
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=pkt)
                st = datapath.send_msg(out)
                print ("{2} Packet output {0} port={1} PKT=\n{3}".format(st, out_ofport, dpid, pkt))

        elif switch.type == VXLAN_GATEWAY:
            if eth.dst == L2_BROADCAST:
                vxlan_ports = switch.vni_OFport[vni][:]
                if in_port in vxlan_ports: # Incoming traffic
                    # Add reverse rule for uni-cast packet.
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    self.mac_vni_to_hostip[(eth.src, vni)] = switch.host_ip
                    actions = [parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print ("{4} Rule added {0} table=1, priority=100, match(tunnel_id={1}, eth_dst={2}, out_port={3}".format(
                        st, vni, eth.src, in_port, dpid, ))

                    # Set tunnel ID and Flood.
                    vlan_id = switch.mapping[vni][0]
                    actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                               OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                               parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                              actions=actions, data=pkt)
                    st = datapath.send_msg(out)
                    print("{0} Incoming traffic output {1} port=OFPP_FLOOD PKT=\n{2}".format(dpid, st, pkt))

                else:  # Outgoing traffic
                    # Add a reverse rule that sets VLAN ID and forwards to the local port.
                    vlan_id = switch.mapping[vni][0]
                    match = parser.OFPMatch(tunnel_id=vni, eth_dst=eth.src)
                    actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q), OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
                               parser.OFPActionOutput(port=in_port)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                            instructions=inst)
                    st = datapath.send_msg(mod)
                    print ("{0} Reverse rule added {1}, match(vni={0}, eth_dst={2}) actions(setVLANID={3}, output={4}".format(
                        dpid, st, vni, vlan_id, in_port))

                    # multicast on all VXLAN ports
                    for port in vxlan_ports:
                        actions = [parser.OFPActionOutput(port=port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
                                                  actions=actions, data=pkt)
                        st = datapath.send_msg(out)
                        print ("{2} Outgoing traffic output {0} port={1} PKT=\n{3}".format(st, port, dpid, pkt))












            #
            #
            #
            #
            #
            #     vxlan_ports = switch.vni_OFport[vni][:]
            #     if in_port in vxlan_ports:  # Incoming traffic
            #         # Add a VLAN tag and flood.
            #         vlan_id = switch.mapping[vni][0]
            #         actions = [OFPActionPushVlan(ether_types.ETH_TYPE_8021Q), OFPActionSetField(vlan_vid=(0x1000 | vlan_id)),
            #                    parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            #         out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
            #                                   actions=actions, data=pkt)
            #         st = datapath.send_msg(out)
            #         print("{0} Incoming traffic output {1} port=OFPP_FLOOD PKT=\n{2}".format(dpid, st, pkt))
            #     else:  # Outgoing traffic
            #         # output on all VXLAN ports.
            #         for port in vxlan_ports:
            #             actions = [parser.OFPActionOutput(port=port)]
            #             out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
            #                                       actions=actions, data=pkt)
            #             st = datapath.send_msg(out)
            #             print ("{2} Outgoing traffic output {0} port={1} PKT=\n{3}".format(st, port, dpid, pkt))
            #
            # ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            # if ipv4_pkt is not None:
            #     try:
            #         remote_ip = self.mac_vni_to_hostip[(eth.dst, vni)]
            #     except KeyError:
            #         print ("ping from other side")  # You can do better
            #         return
            #
            #     out_ofport = switch.vni_remoteip_to_ofport[(vni, remote_ip)]
            #     match = parser.OFPMatch(tunnel_id=vni, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_pkt.dst)
            #     actions = [parser.OFPActionOutput(port=out_ofport)]
            #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            #     mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)
            #     st = datapath.send_msg(mod)
            #     print("{0} Rule added {1} table=1, priority=100, match(tunnel_id={2}, IP, ipv4_dst={3}), Output={4}".format(
            #         dpid, st, vni, ipv4_pkt.dst, out_ofport))
            #     out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port,
            #                               actions=actions, data=pkt)
            #     st = datapath.send_msg(out)
            #     print ("{0} packet out {1} port={2} PKT=\n{3}".format(dpid, dpid, st, out_ofport, pkt))
            #
            #
