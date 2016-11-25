# # -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

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
    def __init__(self, dpid, mapping=None, type=VXLAN_ENABLED):
        self.dpid = dpid
        self.type = type  # Either VXLAN_GATEWAY or VXLAN_ENABLED
        self.mapping = mapping

    def __repr__(self):
        return "Switch: type= {0} dpid= {1} mapping= {2}".format(self.type, self.dpid, self.mapping)


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
            pdb.set_trace()
            self.switches[dpid] = Switch(dpid=dpid, type=type, mapping=new_mapping)

        pdb.set_trace()

    def __init__(self, *args, **kwargs):
        super(VtepConfigurator, self).__init__(*args, **kwargs)
        self.switches = {} # data-paths that are being controlled by this controller.
        self.ip_vni = {}  # Server IP address -> subscribed VNIs
        self._read_config(file_name="CONFIG.json")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def connection_up_handler(self, ev):
        def _add_default_resubmit_rule(next_table_id=1):
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(next_table_id)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
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
                    print (vni, vlan)
                    # TODO : A lot

            _add_default_resubmit_rule(next_table_id=1)  # All other packets should be submitted to 1
        else:
            pdb.set_trace()
            raise VtepConfiguratorException(dpid)




