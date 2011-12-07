//
//  AppDelegate.h
//  MacSnifferGUI
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "PcapSniffer.h"

@interface AppDelegate : NSObject <NSApplicationDelegate>{
    PcapSniffer* ps;
}

@property (assign) IBOutlet NSWindow *window;
@property (retain) IBOutlet NSTableView *tv;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;
- (IBAction) scanAction:(id) sender;
- (IBAction) networkFound:(id) sender;

@end
