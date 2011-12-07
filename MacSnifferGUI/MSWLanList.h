//
//  MSWLanList.h
//  MacSniffer
//
//  Created by Quentin  Swain on 12/6/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MSWLanList : NSObject{
}
@property (retain) NSMutableDictionary* wlanDict;
@property (retain) NSMutableSet* wlanArray;


-(void)insertWlanBSSID:(NSString*) bssid                                        intoDict:dc;

-(void) insertWlanSSID:(NSString *) name
              intoDict:dc;
-(void)insertWlanEntry:(NSString*) bssid name:(NSString*) ssid;
-(id)init;
+ (MSWLanList*) msWlanList;
@end
