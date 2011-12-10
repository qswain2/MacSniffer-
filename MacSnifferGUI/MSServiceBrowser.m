//
//  ServiceBrowser.m
//  MacSniffer
//
//  Created by Quentin  Swain on 12/9/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import "MSServiceBrowser.h"

@implementation MSServiceBrowser 

@synthesize browser;
@synthesize services;
@synthesize servicesArrController;

+(MSServiceBrowser*) new{
    MSServiceBrowser* sb = [[MSServiceBrowser alloc] init];
    return sb;
}
- (id) init {
    
    if ( self = [super init] ) { 
        self.browser = [NSNetServiceBrowser new];
        self.services = [NSMutableArray new];
        self.servicesArrController = [NSArrayController new];
        self.browser.delegate = self;
        
    }
    
    return self; 
}

-(void)netServiceBrowser:(NSNetServiceBrowser *)aBrowser didFindService:(NSNetService *)aService moreComing:(BOOL)more {
    [self.servicesArrController addObject:aService];
    NSString* servName = aService.name;
    NSString* servType = aService.type;
    NSInteger port = aService.port;
    NSLog(@"Service Name:%@ \n Service type:%@ \n Service Port:%d \n",servName,servType,port);
}
-(void)netServiceBrowser:(NSNetServiceBrowser *)aBrowser didRemoveService:(NSNetService *)aService moreComing:(BOOL)more{
    [servicesArrController removeObject:aService];

}
@end
