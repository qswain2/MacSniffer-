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

@synthesize servicesArrController;

+(MSServiceBrowser*) new{
    MSServiceBrowser* sb = [[MSServiceBrowser alloc] init];
    return sb;
}
- (id) init {
    
    if ( self = [super init] ) { 
        self.browser = [[NSNetServiceBrowser alloc] init];
        services = [NSMutableArray new];
        self.servicesArrController = [NSArrayController new];
      
        self.browser.delegate = self;
        
    }
    
    return self; 
}

-(void) netServiceBrowserWillSearch:(NSNetServiceBrowser *)aNetServiceBrowser
{
    NSLog(@"Beginning Service Scan");
}

-(void) netServiceBrowserDidStopSearch:(NSNetServiceBrowser *)aNetServiceBrowser
{
    NSLog(@"Service scan stopped");
}

-(void) netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didNotSearch:(NSDictionary *)errorDict
{
    NSLog(@"Service scan will not occur");
    NSString* errKey;
    NSString* errVal;
    for(NSString* key in errorDict)
    {
        errKey = key;
        errVal = [errorDict valueForKey:key];
        NSLog(@"Error Key: %@\n Error Value: %@ \n",errKey, errVal);
    }
    
}

-(void)netServiceBrowser:(NSNetServiceBrowser *)aBrowser didFindService:(NSNetService *)aService moreComing:(BOOL)more {
    [services addObject:aService];
    NSString* servName = aService.name;
    NSString* servType = aService.type;
    NSInteger port = aService.port;
    NSLog(@"Service Name:%@ \n Service type:%@ \n Service Port:%lu \n",servName,servType,port);
}
-(void)netServiceBrowser:(NSNetServiceBrowser *)aBrowser didRemoveService:(NSNetService *)aService moreComing:(BOOL)more{
    [services removeObject:aService];

}
@end
