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

-(void)insertWlanEntry:(NSString*) bssid
        withName:(NSString*) ssid;
-(id)init;
+ (MSWLanList*) msWlanList;
@end
