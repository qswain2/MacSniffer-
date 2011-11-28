//
//  PcapSniffer.h
//  MacSniffer
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <pcap.h>
@interface PcapSniffer : NSObject{

    pcap_t* handle; 
    char errbuf[PCAP_ERRBUF_SIZE];
    NSString* device;
    NSString* filterString;
    struct bpf_program compiledFilter;
    int timeout;
    int snaplen;
    int promiscuousMode;
    int monitorMode;
    const u_char* packet;
}

-(pcap_t* ) handle;
-(void) setHandle:(pcap_t*) hdl;
-(NSString*) device;
-(void) setDevice:(NSString*) devName;
-(void) memsetForErrbuf;
-(NSString*) filterString;
-(void) setFilterString:(NSString*) filter;
-(void) setFiltertoCString:(char*)filterCString;
-(int) compileFilter;
-(int) timeout;
-(void) setTimeout:(int)to;
-(int) snaplen;
-(void) setSnaplen:(int)sl;
-(int) promiscuousMode;
-(void) setPromiscuousMode;
-(int) monitorMode;
-(void) setMonitorMode:(int) rfmon;
-(int) pc_create_handle;
-(int) pc_set_rfmon;
-(int) pc_set_promisc;
-(int) pc_set_timeout;
-(int) pc_activate_handle;
-(int) pc_compile;
-(void) pc_dispatch;


@end
