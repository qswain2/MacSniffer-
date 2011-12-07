//
//  AppDelegate.h
//  MacSnifferGUI
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "PcapSniffer.h"
@class  CWInterface, CWConfiguration, CWNetwork, SFAuthorizationView;
@interface AppDelegate : NSObject <NSApplicationDelegate>{
    PcapSniffer* ps;
}


@property (assign) IBOutlet NSWindow *window;
@property (retain) IBOutlet NSTableView *wlantv;
@property (retain) NSMutableArray* wlans;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;
- (IBAction) scanAction:(id) sender;
- (IBAction) joinNetworkAction:(id) sender;
- (NSInteger) numberOfRowsInTableView:(NSTableView *)table;
- (id) tableView: (NSTableView *)table objectValueForTableColumn: (NSTableColumn *)column row: (NSInteger)row;
-(void) tableView: (NSTableView *)table
            setObjectValue: (id)object
            forTableColumn: (NSTableColumn *)column
              row: (NSInteger)row;
                                                                   


@end
