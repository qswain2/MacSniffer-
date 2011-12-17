//
//  IEEE_80211.h
//  MacSniffer
//
//  Created by Quentin  Swain on 11/27/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#ifndef MacSniffer_IEEE_80211_h
#define MacSniffer_IEEE_80211_h

#import "Foundation/Foundation.h"
#import "MSWLanList.h"
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
 // Current Acucess Point Address
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

// Read int[] and return NSString object for the Mac Address of
//  the BSSID for a detected WLan
NSString* readBSSID(u_char* addr){
    
    NSMutableString* bssid=[NSMutableString stringWithString:@""];
    NSMutableString* temp;
    
    int z = 6;
    
    do{
       temp= [NSString stringWithFormat:@"%s%02X",((z==6)?" ":":"),*addr++];
       bssid = [bssid stringByAppendingString:temp];
    }while(--z>0);
    NSLog(@"%@",bssid);
    printf("\n");
      
    return bssid;
    
}

//Read the SSID length and extracts the SSID value from the SSID
// struct
NSString* readSSID(struct wi_ssid pkt_ssid ){
    if(pkt_ssid.length == 0)
    {
         NSMutableString* wlanID=[NSMutableString stringWithString:@"Wildcard SSID"];
        return wlanID;
    }
    if(pkt_ssid.length > 0)
    {
        NSMutableString* wlanID=[NSMutableString stringWithString:@""];
        NSMutableString*temp = nil;
        for(int i =0; i < pkt_ssid.length;i++)
        {
            temp =[NSString stringWithFormat:@"%c",(char)pkt_ssid.SSID[i]];
            wlanID = [wlanID stringByAppendingString:temp];
        }
        printf("\n");
     
        char ssidName[pkt_ssid.length];
        
        for(int i =0; i < pkt_ssid.length;++i)
        {
            ssidName[i] = pkt_ssid.SSID[i];
        }
        NSString* compare = [NSString stringWithUTF8String:ssidName];
        
        if ( compare==nil || compare==@"")
            {
                return nil;
            }
        NSLog(@"SSID is %@",wlanID);
        NSLog(@"Compared to %@",compare);
        return wlanID; 
        
    }
    else{printf("there is a problem");}
    return nil;
};

void processPacket(void *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    // ints for the type and subtype calue of the packets
    int tp,stp;
    MSWLanList* dict = (__bridge MSWLanList*)arg;
    struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;
    struct wi_frame *fr= NULL;
    fr =(struct wi_frame *)(packet + rh->it_len);
    // String objects for the information we want to extract from
    //packet scanning
    NSString* name;
    NSString* bssid;
    u_char *ptr;
    
    // get the type and subtype values
    tp = fr->fc.type;
    stp =fr->fc.subtype;
   
    // Handle managementpackets and subtypes 
    if (tp == 0)
    {
        printf("Management packet \n");
        switch(stp){
            // handle subtypes and extract data     
            case ASSOC_REQUEST:
                printf("Association Request \n");
                struct assoc_req_frame* ar = (struct assoc_req_frame *) (packet + rh->it_len);
                printf("SSID len: %d \n",ar->ssid.length);
                name =readSSID(ar->ssid);
                ptr = ar->bssid;
                bssid = readBSSID(ptr);
                if((name != nil) &&(bssid !=nil))
                {
                    [dict insertWlanEntry:bssid name:name];
                }
                break;
                
                case ASSOC_RESP:
                printf("Association Response \n");
                break;
            case REASSOC_REQUEST:
                printf("Reassociation Resquest \n");
                struct reassoc_req_frame* rar = (struct reassoc_req_frame *) fr;
                name =readSSID(rar->ssid);
                ptr = rar->bssid;
                bssid = readBSSID(ptr);
                if((name != nil) &&(bssid !=nil))
                {
                    [dict insertWlanEntry:bssid name:name];
                }
                break;
            case REASSOC_RESP:
               // printf("Reassociation Response \n");
                break;   
            case PROBE_REQUEST:
                printf("Probe Request \n");
                struct probe_req_frame* pr = (struct probe_req_frame *) fr;
                name= readSSID(pr->ssid);
                ptr = pr->bssid;
                bssid = readBSSID(ptr);
                if((name != nil) &&(bssid !=nil))
                {
                    [dict insertWlanEntry:bssid name:name];
                }
                break;
                
            case PROBE_RESP:
                printf("Probe Resonse \n");
                break;
             case BEACON:
                printf("Beacon Frame \n");
                struct beacon_frame *bf = (struct beacon_frame* )fr;
                name = readSSID(bf->ssid);
                bssid = readBSSID(bf->bssid);
                if((name != nil) && (bssid !=nil))
                {
                    [dict insertWlanEntry:bssid name:name];
                }
                // Original code for printing out the mac addresses moved into function readBSSID
                int z = 6;
                   
                ptr = bf->da;
                printf("Dest Addr:");
                do{
                    printf("%s%02X",(z==6)?" ":":",*ptr++);
                }while(--z>0);
                printf("\n");
                
                z = 6;
                ptr = bf->sa;
                printf("Source Addr");
                do{
                    printf("%s%02X",(z==6)?" ":":",*ptr++);
                }while(--z>0);
                printf("\n");
                
                z = 6;
                ptr = bf->sa;
                printf("BSSID");
                do{
                    printf("%s%02X",(z==6)?" ":":",*ptr++);
                }while(--z>0);
                printf("\n");
                
                break; 
                
            default:
                printf("Can't read subtype \n");
                
            
        }
                
        name = nil;
        ptr = nil;
        bssid =nil;
               
        
    }
   /*
     Code to handle other types of packets Control or Data later
    */
     return;
}

#endif
