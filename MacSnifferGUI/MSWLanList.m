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
@synthesize wlanArray;
- (id) init {
    
    if ( self = [super init] ) { 
        
        [self setWlanDict:[NSMutableDictionary dictionary]];
        [self setWlanArray:[NSMutableArray array ]];
        NSLog(@"Dictionary Created");
        
    }
    
    return self; 
}

-(void) insertWlanBSSID:(NSString *)bssid intoDict:(NSMutableDictionary*) dc {
    
    [dc setObject:bssid forKey:@"bssid"];
}

-(void) insertWlanSSID:(NSString*) name intoDict:(NSMutableDictionary*) dc
{
     [dc setObject:name forKey:@"ssid"];
}
-(void)insertWlanEntry:(NSString *)bssid  name:(NSString*) ssid{
    NSMutableDictionary* dict = [NSMutableDictionary dictionary];
    [self insertWlanSSID:ssid intoDict:dict];
    [self insertWlanBSSID:bssid intoDict:dict];
    [wlanArray addObject:dict];
}
+(MSWLanList*) msWlanList{
    
    MSWLanList* newList = [[MSWLanList alloc]init];
    return newList;
}


@end
