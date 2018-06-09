# -*- coding: utf-8 -*-
import copy

import json

from webob import Response

from ryu.ofproto import ether

from ryu.base import app_manager

from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER

from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import tcp, icmp, arp, ipv4, ethernet, packet

from ryu.topology import event, switches

from ryu.topology.api import get_switch, get_link, get_host

from ryu.app.wsgi import ControllerBase, WSGIApplication

import re

app_manager.require_app('ryu.app.ofctl_rest2')


def retornaLinks():	 
	return listaLinks

class No:
	def __init__ (self, Porta, mac = None): #Classe do tipo nó com atributos Porta e Mac
		self.Porta = Porta
		self.mac = mac

listaLinks = []

def testeLink (link):
	for j in listaLinks:

		#print 'link:    dpidOgm: '+ link.dpidOgm + ' dpidDest: '+ link.dpidDest
		#print 'j:       dpidOgm: '+ j.dpidOgm + ' dpidDest: '+ j.dpidDest
		if (j['dpidOgm'] == link['dpidOgm'] and j['dpidDest'] == link['dpidDest']):
			return
		if (j['dpidDest'] == link['dpidOgm'] and j['dpidOgm'] == link['dpidDest']):
			return	
	listaLinks.append(link)



class L2Switch13 (app_manager.RyuApp):

	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	dic1 = {} #dicionário principal onde será mapeado um IP e um segundo dicionário onde ficarão mapeados dPid e um objeto da classe No

	def __init__(self, *args, **kwargs):

		super(L2Switch13, self).__init__(*args, **kwargs)		

	@set_ev_cls(event.EventSwitchEnter)
	def handler_link_enter(self,ev):
		linksTopologia = copy.copy(get_link(self,None))
		print('--------------------começo teste-------------------------------')
		for l in linksTopologia:	
			print l
			try:
				dpidOgm = re.search('(?<=dpid=)(.*?)(?=,)', str(l)).group(0)
				dpidDest= re.search('(?<=to Port<dpid=)(.*?)(?=,)', str(l)).group(0)
				portaOgm = re.search('(?<=port_no=)(.*?)(?=,)',str(l)).group(0)	
				portaDest = re.search('(?<=dpid='+dpidDest+', port_no=)(.*?)(?=, LIVE>)',str(l)).group(0)					

				#print '\n'+ str(l)
				#print 'dpidOgm: '+ dpidOgm + ', dpidDest: '+ dpidDest + ', portaOgm: '+ portaOgm + ', portaDest: '+ portaDest
				if (dpidOgm != dpidDest):
					novoLink = {}
					novoLink['dpidOgm'] = dpidOgm
					novoLink['dpidDest'] = dpidDest
					novoLink['portaOgm'] = portaOgm
					novoLink['portaDest'] = portaDest
						#infoLinks(dpidOgm = dpidOgm,dpidDest = dpidDest,portaOgm = portaOgm, portaDest = portaDest)
					testeLink (novoLink)
			except:
				pass

	# @set_ev_cls(event.EventLinkDelete)
	# def event_link_delete_handler(self, ev):
	# 	print (ev.link.to_dict())



	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):

		datapath = ev.msg.datapath

		ofproto = datapath.ofproto

		parser = datapath.ofproto_parser

		match = parser.OFPMatch()

		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,

					ofproto.OFPCML_NO_BUFFER)]

		self.add_flow(datapath, 0, match, actions)



	def add_flow(self, datapath, priority, match, actions, buffer_id=None):

		ofproto = datapath.ofproto

		parser = datapath.ofproto_parser


		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,

							actions)]

		if buffer_id:

			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,

						priority=priority, match=match,

						instructions=inst)

		else:

			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,

						match=match, instructions=inst)

		datapath.send_msg(mod)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:

			self.logger.debug("packet truncated: only %s of %s bytes",

							  ev.msg.msg_len, ev.msg.total_len)								  

		msg = ev.msg

		datapath = msg.datapath

		ofproto = datapath.ofproto

		parser = datapath.ofproto_parser

		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)

		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if not eth:

			return

		dst = eth.dst #mac destino
		
		src = eth.src #mac origem

		dpid = datapath.id #número de identificação do switch
		
		p_ip = pkt.get_protocols(ipv4.ipv4)

		p_arp = pkt.get_protocols(arp.arp)

		out_port = ofproto.OFPP_FLOOD #Define a porta de saída para que a rede seja inundada

		actions = [parser.OFPActionOutput(out_port)] #Define a ação a ser executada

		match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src = src)		


		if p_arp: #checa se o pacote é arp
			ip_ogm = p_arp[0].src_ip
			ip_dst = p_arp[0].dst_ip
			mac_porta = No(in_port,src) #cria objeto da classe nó com porta e mac 
			if ip_ogm in self.dic1: #checa se o ip em questão já está no dicionário 1 
				dicio = self.dic1[ip_ogm] #recupera-se o dicionário 2 já existente para aquele IP em questão  
				dicio[dpid] = mac_porta #adiciona o objeto da classe nó ao dicionario 2 com a chave sendo o dPid  
			else:
				dic2={} #crio um dicionário vazio para aquele IP
				dic2[dpid] = mac_porta  #adiciona o objeto da classe nó ao dicionario 2 com a chave sendo o dPid  
				self.dic1[ip_ogm] = dic2 #adiciona o dicionário 2 ao dicionário 1 com a chave sendo o ip_ogm
				
		if p_ip: #faz-se o mesmo processo feito para quando é arp
			ip_ogm= p_ip[0].src
			ip_dst = p_ip[0].dst
			mac_porta = No(in_port,src) 
			if ip_ogm in self.dic1:
				dicio = self.dic1[ip_ogm]  
				dicio[dpid] = mac_porta
			else:
				dic2={}
				dic2[dpid] = mac_porta 
				self.dic1[ip_ogm] = dic2			
		
			if ip_dst in self.dic1: #Faz a pesquisa no dicionário 1 para checar se o ip de destino já está mapeado para algum dicionário 2
				dicionario = self.dic1[ip_dst] #pega-se a instância de dicionário 2
				#print dicionario
				if dpid in dicionario: #checa se o dpid está mapeado no dicionário 2
					#print ("O ip origem é: "+str(ip_ogm)+". O ip destino é: "+str(ip_dst))
					porta_mac = dicionario[dpid] #recupera o objeto da classe nó referente a chave dpid
					out_port = porta_mac.Porta #recupera o atributo de porta referente ao objeto recuperado
					actions = [parser.OFPActionOutput(out_port)] #Define a porta recuperada como a de saída (sobrescrevendo a inundação)
					match = parser.OFPMatch(in_port=in_port,eth_type=0x0800, eth_dst=dst, eth_src = src,ipv4_src=ip_ogm, ipv4_dst=ip_dst) 
					#match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ip_ogm, ipv4_dst=ip_dst) 
					self.add_flow(datapath,1,match,actions) #adiciona tal mapeamento entre IP e porta destino na tabela de encaminhamento do switch em questão.
	


		data = None

		if msg.buffer_id == ofproto.OFP_NO_BUFFER:

			data = msg.data


		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)


	def _send_packet(self, datapath, port, pkt):

		ofproto = datapath.ofproto

		parser = datapath.ofproto_parser

		pkt.serialize()

		self.logger.info("packet-out %s" % (pkt,))

		data = pkt.data

		actions = [parser.OFPActionOutput(port=port)]

		out = parser.OFPPacketOut(datapath=datapath,

					buffer_id=ofproto.OFP_NO_BUFFER,
					in_port=ofproto.OFPP_CONTROLLER,
					actions=actions,
					data=data)

		datapath.send_msg(out)

