import sys
from scapy.fields import *
from scapy.layers.dot11 import *
from scapy.all import Raw, sendp
import codecs
import struct

"""
#define ANQP_INFO_ANQP_QUERY_LIST                256
#define ANQP_INFO_ANQP_CAPAB_LIST                257
#define ANQP_INFO_VENUE_NAME_INFO                258
#define ANQP_INFO_EMERGENCY_CALL_NUMBER_INFO     259
#define ANQP_INFO_NETWORK_AUTH_TYPE_INFO         260
#define ANQP_INFO_ROAMING_CONSORTIUM_LIST        261
#define ANQP_INFO_IP_ADDR_TYPE_AVAILABILITY_INFO 262
#define ANQP_INFO_NAI_REALM_LIST                 263
#define ANQP_INFO_3GPP_CELLULAR_NETWORK_INFO     264
#define ANQP_INFO_AP_GEOSPATIAL_LOCATION         265
#define ANQP_INFO_AP_CIVIC_LOCATION              266
#define ANQP_INFO_AP_LOCATION_PUBLIC_ID_URI      267
#define ANQP_INFO_DOMAIN_NAME_LIST               268
#define ANQP_INFO_EMERGENCY_ALERT_ID_URI         269
#define ANQP_INFO_TDLS_CAPAB_INFO                270
#define ANQP_INFO_EMERGENCY_NAI                  271
#define ANQP_INFO_NEIGHBOR_REPORT                272
#define ANQP_INFO_QUERY_AP_LIST                  273
#define ANQP_INFO_AP_LIST_RESPONSE               274
#define ANQP_INFO_FILS_REALM_INFO                275
#define ANQP_INFO_CAG                            276
#define ANQP_INFO_VENUE_URL                      277
#define ANQP_INFO_ADVICE_OF_CHARGE               278
#define ANQP_INFO_LOCAL_CONTENT                  279
#define ANQP_INFO_NETWORK_AUTH_TYPE_TIMESTAMP    280
#define ANQP_INFO_ANQP_VENDOR_SPECIFIC_LIST    56797
"""

gas_types = {
    10: 'GAS Initial Request',
    11: 'GAS Initial Response',
    12: 'GAS Comeback Request',
    13: 'GAS Comeback Response'
}

class Dot11uGASAction(Packet):
    name = "802.11 GAS Action Frame"
    fields_desc = [
                    ByteField("category", 4), # Public action frame
                    ByteEnumField('action', 10, gas_types),
                    ByteField("dialogToken", 0),
                    ]

class Dot11uGASInitialRequest(Packet):
    name = "802.11 GAS Initial Request ANQP Frame"
    fields_desc = [
                    ByteField("tagNumber", 0x6c), # ANQP
                    ByteField("tagLength", 2), # Tag length as from 802.11u
                    BitField("pameBI", 0, 1),
                    BitField("queryResponse", 0, 7),
                    ByteField("advProtocol", 0), # ANQP
                    LenField("queryLength", 0, fmt='<H'),
                    ]
    def post_build(self, p, pay):
        if not self.queryLength:
            self.queryLength = len(pay)
            p = p[:-2]+struct.pack('<H', self.queryLength)
        return p+pay

class Dot11uGASInitialResponse(Packet):
    name = "802.11 GAS Initial Response ANQP Frame"
    fields_desc = [
                    LEShortField("status", 0),
                    LEShortField("comebackDelay", 0),
                    ByteField("tagNumber", 0x6c), # ANQP
                    ByteField("tagLength", 2), # Tag length as from 802.11u
                    BitField("pameBI", 0, 1),
                    BitField("queryResponse", 0, 7),
                    ByteField("advProtocol", 0), # ANQP
                    LenField("responseLength", 0, '<H'),
                    ]

class ANQPElementHeader(Packet):
    name = "ANQP Element"
    fields_desc = [
                    LEShortField("element_id", 0),
                    ]

class ANQPQueryList(Packet):
    name = "ANQP Query List"
    fields_desc = [
                    LEFieldLenField("length", None, length_of="element_ids"),
                    FieldListField("element_ids",[],LEShortField('element_id', 0), 
                                   length_from=lambda pkt:pkt.length)
                    ]

class ANQPCapabilityList(Packet):
    name = "ANQP Capability List"
    fields_desc = [
                    LEFieldLenField("length", None, length_of="element_ids"),
                    FieldListField("element_ids",[],LEShortField('element_id', 0), 
                                   length_from=lambda pkt:pkt.length)
                    ]

class ANQPVenueName(Packet):
    name = "ANQP Venue Name"
    fields_desc = [
                    FieldLenField("length", None, "data", "<H", adjust=lambda pkt,x:x+2),
                    ByteField("venue_group", 0),
                    ByteField("venue_type", 0),
                    StrLenField("data", "", length_from=lambda x: x.length-2)
                    ]

bind_layers( Dot11, Dot11uGASAction, subtype=0x0d, type=0)
bind_layers( Dot11uGASAction, Dot11uGASInitialRequest, category=4, action=10)
bind_layers( Dot11uGASAction, Dot11uGASInitialResponse, category=4, action=11)
bind_layers( Dot11uGASInitialResponse, ANQPElementHeader, advProtocol=0, tagNumber=0x6c)
bind_layers( Dot11uGASInitialRequest, ANQPElementHeader, advProtocol=0, tagNumber=0x6c)
bind_layers( ANQPElementHeader, ANQPQueryList, element_id=256)
bind_layers( ANQPElementHeader, ANQPCapabilityList, element_id=257)
bind_layers( ANQPElementHeader, ANQPVenueName, element_id=258)
bind_layers( ANQPCapabilityList, ANQPElementHeader)
bind_layers( ANQPVenueName, ANQPElementHeader)


interface = 'wlx00c0caaa55cf'
sender = 'aa:aa:aa:bb:bb:bb'
dest = 'ff:ff:ff:ff:ff:ff'
dest_2 = 'ff:ff:ff:ff:ff:ff'
ubiq = 'ff:ff:ff:ff:ff:ff'
home = 'ff:ff:ff:ff:ff:ff'

target = sys.argv[1]

dot11 = Dot11(
    type=0,
    subtype=0x000d,
    addr1=target,
    addr2=sender,
    addr3=sender
)

anqp_query_element_ids = [
    264, # 3GPP Cellular Network information
    261, # Roaming Consortium list
    263, # NAI Realm list
    268, # Domain name list
]

frame = (RadioTap()
    /Dot11(
        type=0,
        subtype=0x000d,
        addr1=target,
        addr2=sender,
        addr3=target,
        addr4=target
    )
    /Dot11uGASAction(action="GAS Initial Request", dialogToken=1)
    /Dot11uGASInitialRequest()
    /ANQPElementHeader(element_id=256)
    /ANQPQueryList(element_ids=list(range(256,280)))
)


#sendp(frame, iface=interface, inter=3, loop=1)
sendp(frame, iface="wlan3", inter=3, loop=1)
