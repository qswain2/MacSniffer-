//
//  IEEE_80211.h
//  MacSniffer
//
//  Created by Quentin  Swain on 11/27/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#ifndef MacSniffer_IEEE_80211_h
#define MacSniffer_IEEE_80211_h

/* Original C Code  Declarations*/ 
 #define MAXBYTES2CAPTURE 65535
 #define MANAGEMNT 0
 #define ASSOC_REQUEST 0
 #define ASSOC_RESP 1
 #define REASSOC_REQUEST 2
 #define REASSOC_RESP 3
 #define PROBE_REQUEST 4
 #define PROBE_RESP 5
 #define BEACON 8
 
 
 
 struct ieee80211_radiotap_header{
 u_int8_t it_version;
 u_int8_t it_pad;
 u_int16_t it_len;
 u_int32_t it_present;
 };
 
 struct frame_control
 {
 unsigned int protoVer:2;  //protocol version
 unsigned int type:2; //frame type field (Management,Control,Data)
 unsigned int subtype:4; // frame subtype
 
 unsigned int toDS:1; // frame coming from Distribution system 
 unsigned int fromDS:1; //frame coming from Distribution system 
 unsigned int moreFrag:1; // More fragments?
 unsigned int retry:1; //was this frame retransmitted
 
 unsigned int powMgt:1; //Power Management
 unsigned int moreDate:1; //More Date
 unsigned int protectedData:1; //Protected Data
 unsigned int order:1; //Order
 };
 struct wi_frame {
 struct frame_control fc;
 u_int16_t wi_duration;
 u_int8_t wi_add1[6];
 u_int8_t wi_add2[6];
 u_int8_t wi_add3[6];
 u_int16_t wi_sequenceControl;
 // u_int8_t wi_add4[6];
 //unsigned int qosControl:2;
 //unsigned int frameBody[23124];
 };
 
 struct wi_ssid{
 u_int8_t elementID;
 u_int8_t length;
 u_int8_t SSID[32];
 };
 
 struct beacon_frame{
 u_int16_t fc;
 u_int16_t duration;
 u_int8_t da[6];
 u_int8_t sa[6];
 u_int8_t bssid[6];
 u_int16_t sequenceControl;
 u_int8_t timestamp[8];
 u_int16_t beaconInterval;
 u_int16_t capability;
 struct wi_ssid  ssid;
 
 };
 struct assoc_req_frame{
 u_int16_t fc;
 u_int16_t duration;
 u_int8_t da[6];
 u_int8_t sa[6];
 u_int8_t bssid[6];
 u_int16_t sequenceControl;
 u_int16_t capability;
 u_int16_t listenInterval;
 struct wi_ssid ssid;
 };
 struct reassoc_req_frame{
 u_int16_t fc;
 u_int16_t duration;
 u_int8_t da[6];
 u_int8_t sa[6];
 u_int8_t bssid[6];
 u_int16_t sequenceControl;
 u_int16_t capability;
 u_int16_t listenInterval;
 // Current Access Point Address
 u_int8_t currAP[6];
 struct wi_ssid ssid;
 };
 struct probe_req_frame{
 u_int16_t fc;
 u_int16_t duration;
 u_int8_t da[6];
 u_int8_t sa[6];
 u_int8_t bssid[6];
 u_int16_t sequenceControl;
 struct wi_ssid ssid;
 
 };
 struct probe_response_frame{
 u_int16_t fc;
 u_int16_t duration;
 u_int8_t da[6];
 u_int8_t sa[6];
 u_int8_t bssid[6];
 u_int16_t sequenceControl;
 u_int8_t timestamp[8];
 u_int16_t beaconInterval;
 u_int16_t capability;
 
 };
 


#endif
