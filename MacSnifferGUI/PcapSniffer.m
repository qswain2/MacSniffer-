//
//  PcapSniffer.m
//  MacSniffer
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import "PcapSniffer.h"

@implementation PcapSniffer

-(pcap_t*) handle{
    return handle;
}
-(void) setHandle:(pcap_t*) hdl{
    handle = hdl;
}
-(NSString*) device{
    return device;
}
-(void) setDevice:(NSString*) devName{
    device = devName;
}

-(void) memsetForErrbuf{
    memset(errbuf,0,PCAP_ERRBUF_SIZE);
}
-(NSString*) filterString{
    return filterString;
}

-(void) setFilterString:(NSString *)filter{
    filterString = filter;
}
-(void) setFiltertoCString:(char *)filterCString{

}

-(struct bpf_program*)compiledFilter{
    return &compiledFilter;
}
-(int) timeout{
    return timeout;
}

-(void) setTimeout:(int)to{
    timeout = to;
}

-(int) snaplen{
    return snaplen;
}

-(void) setSnaplen:(int)sl{
    snaplen = sl;
}

-(int) promiscuousMode{
    return promiscuousMode;
}

-(void) setPromiscuousMode:(int)pm{
    promiscuousMode = pm;
}

-(int) monitorMode{
    return monitorMode;
}

-(void) setMonitorMode:(int)rfmon{
    monitorMode = rfmon;
}

-(int) pc_create_handle{
    if(device != NULL)
    {
        [self setHandle: pcap_create([device UTF8String], errbuf)];
        if(handle == NULL)
        {
            NSLog(@"There was an error creating the capture handle: %s", errbuf);
            return -1;
        }
        return 0;
    }
    return -2;
}
-(int) pc_set_rfmon{
    return pcap_set_rfmon(handle, monitorMode);
}
-(int) pc_set_promisc{
    return pcap_set_promisc(handle,promiscuousMode);
}

-(int) pc_set_timeout{
    return pcap_set_timeout(handle, timeout);
}

-(int) pc_activate_handle{
    return pcap_activate(handle);
}

-(int) pc_compile{
    return pcap_compile(handle, &compiledFilter, [filterString UTF8String], 0, PCAP_NETMASK_UNKNOWN);
}

-(int) pc_set_filter{
    return pcap_setfilter(handle, &compiledFilter);
}

-(void) pc_dispatch{
    // declare process packet.
    if(pcap_dispatch(handle, 0, processPacket, &count != 0)
       {
           pcap_geterr(handle);
       }
}

    


@end
