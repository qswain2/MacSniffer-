//
//  ServiceBrowser.h
//  MacSniffer
//
//  Created by Quentin  Swain on 12/9/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface MSServiceBrowser : NSObject <NSNetServiceBrowserDelegate>
{
 NSMutableArray* services;
}
@property (retain) NSNetServiceBrowser* browser;
@property (readwrite,retain) NSArrayController* servicesArrController;
 

+(MSServiceBrowser *)new;

@end
