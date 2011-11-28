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

@end
