import json
import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu import utils
from webob import Response

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable/{dpid}'

class MySimpleSwitch2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MySimpleSwitch2, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,
                {simple_switch_instance_name: self})

        self.switches = {}
        self.mac_to_port = {}
        self.s1_ports = [1, 2, 3]
        self.s3_ports = [1, 2, 3]
        self.h2_ip = '10.0.0.2'
        self.h2_mac = '00:00:00:00:00:02'
        self.s3_packet_in = 2
        self.s3_rule_port = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.switches[datapath.id] = datapath

        '''if datapath.id == 3:
            band = [parser.OFPMeterBandDrop(rate=10,burst_size=10)]
            req = parser.OFPMeterMod(datapath, ofproto.OFPMC_ADD,
                    ofproto.OFPMF_KBPS, 1, band)
            datapath.send_msg(req)'''

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions,
                 hard_timeout=0, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                hard_timeout=hard_timeout, flags=flags)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        hard_timeout = 0
        flags = 0

        #s3
        if dpid == 3:
            #No.1 packet_in drop
            if self.s3_packet_in == 2:
                self.s3_packet_in -= 1 
                self.s3_ports.remove(in_port)
                self.s3_rule_port = in_port
                return
            #No.2 packet_in add-flow
            elif self.s3_packet_in == 1:
                self.s3_packet_in -= 1 
                self.mac_to_port[dpid][src] = in_port
                self.s3_ports.remove(in_port)
                out_port = self.s3_ports[0]
                dst = self.h2_mac
               
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=self.s3_rule_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
            #h2 -> h1
            else:
                self.mac_to_port[dpid][src] = in_port
                out_port = self.mac_to_port[dpid][dst]

        else:
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port
            
            hard_timeout = 0
            flags = 1

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions,
                    hard_timeout=hard_timeout, flags=flags)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        self.logger.info('kkk')

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.info('OFPFlowRemoved received: '
                          'reason=%s, packet_count=%d'
                          'match.fields=%s',
                          reason, msg.packet_count, msg.match)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg

        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x'
                ' message=%s',
                msg.type, msg.code, utils.hex_array(msg.data))

class SimpleSwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data,
                **config)
        self.simpl_switch_spp = data[simple_switch_instance_name]

    @route('simpleswitch', url, methods=['GET'],
            requirements={'dpid':dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)
        
        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    '''@route('simpleswitch', url, methods=['PUT'],
            requirements={'dpid':dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):
        simple_switch = self.simpl_switch_spp
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        new_entry = eval(req.body)

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        try:
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            return Response(status=500)'''
