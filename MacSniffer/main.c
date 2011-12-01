//
//  main.c
//  MacSniffer
//
//  Created by Quentin  Swain on 11/20/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//


#include <string.h>
#include <stdlib.h>
#include <pcap.h>
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
    unsigned int protoVer:2; // protocol version
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

void readSSID(struct wi_ssid pkt_ssid ){
    
    if(pkt_ssid.length != 0)
    {
        for(int i =0; i < pkt_ssid.length;i++)
        {
            printf("%c",pkt_ssid.SSID[i]);
        }
        printf("\n");
    
        char ssidName[pkt_ssid.length];
        
        for(int i =0; i < pkt_ssid.length;i++)
        {
            ssidName[i]= (char)pkt_ssid.SSID[i];
        }
        printf("SSID: %s",ssidName);
        
    }
    else{printf("there is a problem");}
   
};
/*
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    
    int tp,stp,i= 0, *counter = (int *) arg;
    struct ieee80211_radiotap_header *rh =(struct ieee80211_radiotap_header *)packet;
    struct wi_frame *fr= (struct wi_frame *)(packet + rh->it_len);
    u_char *ptr;
    
    //printf("Frame Type: %d",fr->wi_fC->type);
    printf("Packet count: %d\n", ++(*counter));
    printf("Received Packet Size: %d \n", pkthdr->len);
    tp = fr->fc.type;
    stp =fr->fc.subtype;
    
    if (tp == 0)
    {
        printf("Management packet \n");
        switch(stp){
        
            case ASSOC_REQUEST:
                printf("Association Request \n");
                struct assoc_req_frame* ar = (struct assoc_req_frame *) (packet + rh->it_len);
                printf("SSID len: %d \n",ar->ssid.length);
                //ssid = readSSID(ar->ssid.SSID, ar->ssid.length);
                //printf("SSID: %s",ssid);
                break;
    
            case ASSOC_RESP:
                printf("Association Response \n");
                break;
            case REASSOC_REQUEST:
                printf("Reassociation Resquest \n");
                struct reassoc_req_frame* rar = (struct reassoc_req_frame *) fr;
                readSSID(rar->ssid);
                break;
            case REASSOC_RESP:
                printf("Reassociation Response \n");
                break;   
            case PROBE_REQUEST:
                printf("Probe Request \n");
                struct probe_req_frame* pr = (struct probe_req_frame *) fr;
                readSSID(pr->ssid);

                break;
            case PROBE_RESP:
                printf("Probe Resonse \n");
                break;
            case BEACON:
                printf("Beacon Frame \n");
                struct beacon_frame *bf = (struct beacon_frame* )fr;
                readSSID(bf->ssid);
              
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
    }
       printf("\n");
   
    for (i = 0;i<pkthdr->len;i++)
    {
        
        if(isprint(packet[i +rh->it_len]))
        {
            printf("%c",packet[i + rh->it_len]);	
        }
        
        else{printf(".");}
        
        
        
        //print newline after each section of the packet
        if((i%16 ==0 && i!=0) ||(i==pkthdr->len-1))
        {
            printf("\n");
	    }
        
    }
    return;
}
*/
int main(int argc, char** argv)
{
    
    int dl,count = 0;
    pcap_t* descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    struct bpf_program fp;
    char filter[]="wlan broadcast";
    const u_char* packet;
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
    
    device = argv[1];
    
    if(device == NULL)
    {
        fprintf(stdout,"Supply a device name ");
        exit(1);
    }
    
    else
    {
        
        descr = pcap_create(device,errbuf);
    
        //settings for pcap
        //Enable monitor mode
    
        if(pcap_set_rfmon(descr,1)!=0)
        {
            perror("Error setting monitor mode");
            exit(1);
        }
        if(pcap_set_promisc(descr,1) !=0)
        {
            perror("Error setting promiscuous mode");
            exit(1);
        }
        if (pcap_set_timeout(descr,10000) != 0)
        {
            perror("Error setting promiscuous mode");
            exit(1);
        }
    
        if (pcap_activate(descr)!=0)
        {
            perror("Error activating capture handle");
            exit(1);
        }
    
        dl =pcap_datalink(descr);
        if(dl != 127)
        {
            fprintf (stderr,"Incorrect datalink type: %d",dl);
            exit(1);
        }
    
        if(pcap_compile(descr,&fp,filter,0,PCAP_NETMASK_UNKNOWN)==-1)
        {
            fprintf(stderr,"Error compiling filter\n");
            exit(1);
        }
    
        if(pcap_setfilter(descr,&fp)==-1)
        {
            fprintf(stderr,"Error setting filter\n");
            exit(1);
        }
    
    //    pcap_loop(descr,0, processPacket, (u_char *) &count);
    
        return 0;
    }
    return -1;
}
