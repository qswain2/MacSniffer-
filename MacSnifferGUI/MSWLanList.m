//
//  MSWLanList.m
//  MacSniffer
//
//  Created by Quentin  Swain on 12/6/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import "MSWLanList.h"

@implementation MSWLanList
@synthesize wlanDict;
- (id) init {
    
    if ( self = [super init] ) { 
        
        [self setWlanDict:[NSMutableDictionary dictionary]];
        NSLog(@"Dictionary Created");
        
    }
    
    return self; 
}
-(void) insertWlanEntry:(NSString *)bssid withName:(NSString *)ssid{
    //set the ssid as the value and the bssid as the key
    //accounts for APs that are part of an ESS
    [wlanDict setObject:ssid forKey:bssid];
    
}
+(MSWLanList*) msWlanList{
    
    MSWLanList* newList = [[MSWLanList alloc]init];
    return newList;
}

@end
