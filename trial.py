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
from ryu.lib.ovs import bridge as ovs_bridge

VXLAN_GATEWAY = 1
VXLAN_ENABLED = 2
class VtepConfiguratorException(Exception):
    def __init__(self, dpid):
        super(VtepConfiguratorException, self).__init__(
            "DPID {0} was not specified in configuration file".format(dpid)
        )


class Switch(object):
    def __init__(self, dpid, host_ip, mapping=None, type=VXLAN_ENABLED):
        self.dpid = dpid
        self.type = type  # Either VXLAN_GATEWAY or VXLAN_ENABLED
        self.mapping = mapping
        self.host_ip = host_ip

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
                new_mapping[int(vni)]  = map(int, dp['mapping'][vni].split(','))

            type = VXLAN_ENABLED if dp['type'] == 'VXLAN_ENABLED' else VXLAN_GATEWAY
            print (new_mapping)

            dpid = int(dp['id'], 16)
            print (config_data)
            self.switches[dpid] = Switch(dpid=dpid, host_ip=dp['host_ip'], type=type, mapping=new_mapping)


    def __init__(self, *args, **kwargs):
        super(VtepConfigurator, self).__init__(*args, **kwargs)
        self.switches = {} # data-paths that are being controlled by this controller.
        self.ip_vni = {}  # Server IP address -> subscribed VNIs
        self._read_config(file_name="CONFIG.json")
        # TODO: generate this mapping dynamically
        self.vni_OFport = {101: [10],
                            102: [10],
                            103: [10]}  # local OF ports which reach the vni


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _connection_up_handler(self, ev):
        def _add_default_resubmit_rule(next_table_id=1):
            #Adds a low priority rule in table 0 to resubmit the unmatched packets to table 1
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(next_table_id)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
            datapath.send_msg(mod)

            #Add a low priority rule in table 1 to forward table-miss to controller
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=0, match=match, instructions=inst)
            datapath.send_msg(mod)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        if dpid in self.switches:
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
                        datapath.send_msg(mod)

            elif switch.type == VXLAN_GATEWAY:
                for vni, vlan in switch.mapping.items():
                    # Add a rule to stip VLAN ID, Add a corresponding VNI and resubmit to 1
                    match = parser.OFPMatch(vlan_vid=vlan)
                    actions = [parser.OFPActionPopVlan(), parser.NXActionSetTunnel(tun_id=vni)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                               parser.OFPInstructionGotoTable(1)]
                    mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                            match=match, instructions=inst)
                    pdb.set_trace()
                    VLAN_VNI_status = datapath.send_msg(mod)
                    print ("VLAN {0} to VNI {1} mapping rule add operation {2}".format(vlan, vni, VLAN_VNI_status))
                    pdb.set_trace()

            _add_default_resubmit_rule(next_table_id=1)  # All other packets should be submitted to 1
        else:
            pdb.set_trace()
            raise VtepConfiguratorException(dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #pdb.set_trace()
        # TODO: It is a good idea to keep timeouts for flow-mods that are in PACKET_IN handler
        # TODO: Add log messages instead of print statements
        msg = ev.msg
        datapath = msg.datapath
        if datapath.id not in self.switches:
            raise VtepConfiguratorException(datapath.id)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        vni = msg.match['tunnel_id']
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        src = eth.src
        dst = eth.dst
        if in_port in self.vni_OFport[vni]:  # This was received from remote server
            pdb.set_trace()
            if dst == 'ff:ff:ff:ff:ff:ff':
                dst_ports = self.vni_OFport[vni]
                for dst_port in dst_ports:
                    actions = [parser.OFPActionOutput(port=dst_port)]
                    # Here again, we can't write a rule, hence outputting at all VXLAN-ports
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=None)
                    packet_out_status = datapath.send_msg(out)
                    print ("Forwarded to local port : {0} operation was {1}".format(dst_port, packet_out_status))

            # Learn the mac of remote VM


        # should this be elif?
        elif dst == 'ff:ff:ff:ff:ff:ff':  # TODO: find a constant in RYU that represents this
            #pdb.set_trace()
            # Adds reverse flow rule for matching on IP address like this
            # table=1,tun_id=200,arp,nw_dst=14.0.0.4,actions=output:2
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt is None:
                print("This was a broadcast packet but not an arp packet")
                print (pkt)
                #pdb.set_trace()
                return
            src_ip = arp_pkt.src_ip
            match = parser.OFPMatch(tunnel_id=vni, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)  # ETH_TYPE_IP ?
            actions = [parser.OFPActionOutput(port=in_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]  # why not OFPIT_APPLY_ACTIONS?
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match,
                                    instructions=inst)  # command = OFPFC_MODIFY

            flow_mod_status = datapath.send_msg(mod)
            print (mod)
            print ("First flow mod ", flow_mod_status)


            # Adds reverse flow rule like this
            # table=1,tun_id=100,dl_dst=fa:16:3e:00:b6:71,actions=output:1
            match = parser.OFPMatch(tunnel_id=vni, eth_dst=src)
            actions = [parser.OFPActionOutput(port=in_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)  # command = OFPFC_MODIFY
            flow_mod_status = datapath.send_msg(mod)
            print ("Second flow mod", flow_mod_status)

            # If it is a broadcast packet then forward on all the local ports that belong to this particular VNI
            ports = self.switches[datapath.id].mapping[vni][:]  # deep copy
            ports.remove(in_port)
            for local_out_port in ports:
                #match = parser.OFPMatch(tunnel_id=vni, eth_dst=dst)
                actions = [parser.OFPActionOutput(port=local_out_port)]
                #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                # Here we can't write OFPFlowMod because the match field will be same for each rule
                # Hence the last one to execute shall overwrite the others.
                # Hence we output the packets at each port.
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=None)
                #mod = parser.OFPFlowMod(datapath=datapath, table_id=1, priority=100, match=match, instructions=inst)
                packet_out_status = datapath.send_msg(out)
                print ("Forwarded to local port : {0} operation was {1}".format(local_out_port, packet_out_status))

            # If it is a broadcast message then output to all VXLAN ports that are subscribed to this vni
            of_ports = self.vni_OFport[vni]
            for vxlan_port in of_ports:
                actions = [parser.OFPActionOutput(port=vxlan_port)]
                # Here again, we can't write a rule, hence outputting at all VXLAN-ports
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=None)
                packet_out_status = datapath.send_msg(out)
                print ("Forwarded to local port : {0} operation was {1}".format(vxlan_port, packet_out_status))



        """
        msg.match['tunnel_id']

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
        eth.ethertype == ether_types.ETH_TYPE_ARP  # If eth request
        dst = eth.dst
        src = eth.src
        """




