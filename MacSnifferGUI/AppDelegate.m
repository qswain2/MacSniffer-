//
//  AppDelegate.m
//  MacSnifferGUI
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import "AppDelegate.h"
#import "IEEE_80211.h"
#import "PcapSniffer.m"
#import "CoreWLAN/CoreWLAN.h"
#import "CoreWLAN/CWInterface.h"

NSString* const CBSSIDIdentifier = @"ssid";
NSString* const CBBSSIDIdentifier =@"bssid";
@implementation AppDelegate


@synthesize window = _window;
@synthesize wlantv= _wlantv;
@synthesize wlans;
@synthesize persistentStoreCoordinator = __persistentStoreCoordinator;
@synthesize managedObjectModel = __managedObjectModel;
@synthesize managedObjectContext = __managedObjectContext;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    ps = [PcapSniffer pcapSniffer];
   
    
    
}

/**
    Returns the directory the application uses to store the Core Data store file. This code uses a directory named "MacSnifferGUI" in the user's Library directory.
 */
- (NSURL *)applicationFilesDirectory {

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *libraryURL = [[fileManager URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask] lastObject];
    return [libraryURL URLByAppendingPathComponent:@"MacSnifferGUI"];
}

/**
    Creates if necessary and returns the managed object model for the application.
 */
- (NSManagedObjectModel *)managedObjectModel {
    if (__managedObjectModel) {
        return __managedObjectModel;
    }
	
    NSURL *modelURL = [[NSBundle mainBundle] URLForResource:@"MacSnifferGUI" withExtension:@"momd"];
    __managedObjectModel = [[NSManagedObjectModel alloc] initWithContentsOfURL:modelURL];    
    return __managedObjectModel;
}

/**
    Returns the persistent store coordinator for the application. This implementation creates and return a coordinator, having added the store for the application to it. (The directory for the store is created, if necessary.)
 */
- (NSPersistentStoreCoordinator *)persistentStoreCoordinator {
    if (__persistentStoreCoordinator) {
        return __persistentStoreCoordinator;
    }

    NSManagedObjectModel *mom = [self managedObjectModel];
    if (!mom) {
        NSLog(@"%@:%@ No model to generate a store from", [self class], NSStringFromSelector(_cmd));
        return nil;
    }

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *applicationFilesDirectory = [self applicationFilesDirectory];
    NSError *error = nil;
    
    NSDictionary *properties = [applicationFilesDirectory resourceValuesForKeys:[NSArray arrayWithObject:NSURLIsDirectoryKey] error:&error];
        
    if (!properties) {
        BOOL ok = NO;
        if ([error code] == NSFileReadNoSuchFileError) {
            ok = [fileManager createDirectoryAtPath:[applicationFilesDirectory path] withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if (!ok) {
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    }
    else {
        if ([[properties objectForKey:NSURLIsDirectoryKey] boolValue] != YES) {
            // Customize and localize this error.
            NSString *failureDescription = [NSString stringWithFormat:@"Expected a folder to store application data, found a file (%@).", [applicationFilesDirectory path]]; 
            
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setValue:failureDescription forKey:NSLocalizedDescriptionKey];
            error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:101 userInfo:dict];
            
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    }
    
    NSURL *url = [applicationFilesDirectory URLByAppendingPathComponent:@"MacSnifferGUI.storedata"];
    NSPersistentStoreCoordinator *coordinator = [[NSPersistentStoreCoordinator alloc] initWithManagedObjectModel:mom];
    if (![coordinator addPersistentStoreWithType:NSXMLStoreType configuration:nil URL:url options:nil error:&error]) {
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    __persistentStoreCoordinator = coordinator;

    return __persistentStoreCoordinator;
}

/**
    Returns the managed object context for the application (which is already
    bound to the persistent store coordinator for the application.) 
 */
- (NSManagedObjectContext *)managedObjectContext {
    if (__managedObjectContext) {
        return __managedObjectContext;
    }

    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:9999 userInfo:dict];
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    __managedObjectContext = [[NSManagedObjectContext alloc] init];
    [__managedObjectContext setPersistentStoreCoordinator:coordinator];

    return __managedObjectContext;
}

/**
    Returns the NSUndoManager for the application. In this case, the manager returned is that of the managed object context for the application.
 */
- (NSUndoManager *)windowWillReturnUndoManager:(NSWindow *)window {
    return [[self managedObjectContext] undoManager];
}

/**
    Performs the save action for the application, which is to send the save: message to the application's managed object context. Any encountered errors are presented to the user.
 */
- (IBAction)saveAction:(id)sender {
    NSError *error = nil;
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing before saving", [self class], NSStringFromSelector(_cmd));
    }

    if (![[self managedObjectContext] save:&error]) {
        [[NSApplication sharedApplication] presentError:error];
    }
}
-(IBAction) scanAction:(id) sender{
    

    NSLog(@"Configuring capture device");
    //Set device and configure capture handle
    [ps setDevice:@"en1"];
    NSLog(@"The device name is: %@", ps.device);
    [ps pc_create_handle];
    [ps pc_set_promisc];
    [ps pc_set_rfmon];
    [ps pc_set_timeout];
    [ps pc_activate_handle];
    
    //Begins actual scan for packets
    NSLog(@"Begin Scan");
    [ps pc_dispatch];
    NSLog(@"End Scan");
    
    // Close capture handle  and release resources 
    [ps pc_close];
    
   
    NSSet* detectedSet = [NSSet setWithArray:ps.wlanList.wlanArray];
    wlans = [[detectedSet allObjects] mutableCopy];
    [self.wlantv reloadData];
}

//Action for getting interface and ascoiating to a selected network using CoreWirelessLan Framework
-(IBAction) joinNetworkAction:(id)sender{
    NSLog(@"Join Button Clicked");
    //Code to attempt network association
    // is a network from the list has been selected 
    if(self.wlantv.selectedRow > -1)
    {
        NSError* err = nil;
        NSInteger selectedIndex = [self.wlantv selectedRow];
        NSMutableDictionary* wlanInfo= [wlans objectAtIndex:selectedIndex];
        NSString* itfname = @"en1";
        CWInterface* itf = [CWInterface interfaceWithName:itfname];
        NSLog(@"Current interface obj:%@",[itf interfaceName]);
        CW8021XProfile* wlanProfile = [CW8021XProfile profile];
        wlanProfile.ssid = [wlanInfo valueForKey:@"ssid"];
        NSLog(@" BEgin Network Scan for %@",[wlanInfo valueForKey:@"ssid"]);
        [itf disassociate];
        NSSet* networks = [NSSet setWithSet:[itf scanForNetworksWithName:[wlanInfo valueForKey:@"ssid"] error:&err]];
        if(err)
        {
            NSLog(@"Error: %@",[err localizedDescription]);
            [NSApp presentError:err];
        }
        else{
            NSLog(@"Number of Networks found: %lu",networks.count);
            NSLog(@"Network Scan complete");
            NSMutableDictionary* params =[NSMutableDictionary dictionaryWithCapacity:0];
            NSLog(@"Attempt Association");
           /*
            Associate to network code 
            
            */
        }
    }
}

- (NSInteger) numberOfRowsInTableView:(NSTableView *)table {
    return [wlans count];
}
-(id) tableView: (NSTableView *)table objectValueForTableColumn: (NSTableColumn *)column
            row: (NSInteger)row{
    NSDictionary* wlan = [[self wlans] objectAtIndex: row];
    NSString* identifier = column.identifier;
    return [wlan objectForKey:identifier];
}
-(void) tableView: (NSTableView *)table
   setObjectValue: (id)object
   forTableColumn: (NSTableColumn *)column
              row: (NSInteger)row;{
    NSMutableDictionary* wlan = [self.wlans objectAtIndex:row];
    NSString* identifier = column.identifier;
    [wlan setObject:object forKey:identifier];
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {

    // Save changes in the application's managed object context before the application terminates.

    if (!__managedObjectContext) {
        return NSTerminateNow;
    }

    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing to terminate", [self class], NSStringFromSelector(_cmd));
        return NSTerminateCancel;
    }

    if (![[self managedObjectContext] hasChanges]) {
        return NSTerminateNow;
    }

    NSError *error = nil;
    if (![[self managedObjectContext] save:&error]) {

        // Customize this code block to include application-specific recovery steps.              
        BOOL result = [sender presentError:error];
        if (result) {
            return NSTerminateCancel;
        }

        NSString *question = NSLocalizedString(@"Could not save changes while quitting. Quit anyway?", @"Quit without saves error question message");
        NSString *info = NSLocalizedString(@"Quitting now will lose any changes you have made since the last successful save", @"Quit without saves error question info");
        NSString *quitButton = NSLocalizedString(@"Quit anyway", @"Quit anyway button title");
        NSString *cancelButton = NSLocalizedString(@"Cancel", @"Cancel button title");
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:question];
        [alert setInformativeText:info];
        [alert addButtonWithTitle:quitButton];
        [alert addButtonWithTitle:cancelButton];

        NSInteger answer = [alert runModal];
        
        if (answer == NSAlertAlternateReturn) {
            return NSTerminateCancel;
        }
    }

    return NSTerminateNow;
}

@end
