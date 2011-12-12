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
#import "MSServiceBrowser.m"

NSString* const CBSSIDIdentifier = @"ssid";
NSString* const CBBSSIDIdentifier =@"bssid";
NSString* const CBServiceIdentifier = @"ServiceName";
NSString* const CBTypeIdentifier = @"ServiceType";
@implementation AppDelegate


@synthesize window = _window;
@synthesize wlantv= _wlantv;
@synthesize wlans;
@synthesize services;

@synthesize persistentStoreCoordinator = __persistentStoreCoordinator;
@synthesize managedObjectModel = __managedObjectModel;
@synthesize managedObjectContext = __managedObjectContext;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    ps = [PcapSniffer pcapSniffer];
    serviceBrowser = [MSServiceBrowser new];
    
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
    
    //Update the outlet to point at the detectedSet Object
    NSSet* detectedSet = [NSSet setWithArray:ps.wlanList.wlanArray];
    wlans = [[detectedSet allObjects] mutableCopy];
   
    //message the tableview to update itself;
    [self.wlantv reloadData];
}

//Action for getting interface and associating to a selected network using CoreWirelessLan Framework
-(IBAction) joinNetworkAction:(id)sender{
       
   
               //Get the index value of the item currently selected in the table view
        NSInteger selectedIndex = [self.wlantv selectedRow];
        
        //Check for selected Items 
        if(selectedIndex > -1)
        {
            //Create error object
            NSError* err = nil;
            NSMutableDictionary* wlanInfo= [wlans objectAtIndex:selectedIndex];
            
            NSString* itfname = @"en1";
            CWInterface* itf = [CWInterface interfaceWithName:itfname];
         
            NSLog(@"Interface Created");
            CW8021XProfile* wlanProfile = [CW8021XProfile profile];
            wlanProfile.ssid = [wlanInfo valueForKey:@"ssid"];
            
            NSLog(@" BEgin Network Scan for %@",[wlanInfo valueForKey:@"ssid"]);
            [itf disassociate];
            NSSet* networks = [NSSet setWithArray:[itf scanForNetworksWithParameters: wlanInfo error:&err]];
          //  NSSet* networks = [NSSet setWithSet:[itf scanForNetworksWithName:[wlanInfo valueForKey:@"ssid"] error:&err]];
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
                if (networks.count > 0){
                
                    NSEnumerator* netEnum= [networks objectEnumerator];
                    CWNetwork* net = [netEnum nextObject];
                
                    //[itf associateToNetwork:net withParameters:nil error:&err];
                    if(err)
                    {
                        NSLog(@"Error: %@",[err localizedDescription]);
                        [NSApp presentError:err];
                    }
                
                    else
                    {
                        NSLog(@"Association Successful");
                        [serviceBrowser.browser searchForServicesOfType:@"_airport._tcp" inDomain:@""];
                    
                    }
                }
            }
        }
    else
    { 
        NSAlert *missingSelection = [[NSAlert alloc]init];
        //Alert user about selecting item in table view
        [missingSelection addButtonWithTitle:@"OK"];
        [missingSelection setMessageText:@"Must select a WLan for association"];
        [missingSelection setInformativeText:@"Must select a WLan for association"];
        if ([missingSelection runModal] == NSAlertFirstButtonReturn) {
            
            
            
        }
         
    }
}


/****** NSTableView Protocol Messages*******/
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
/****** NSTableView Protocol Messages*******/
 
/****** NSNetServiceDelegate Protocol Messages*******/
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
/****** NSNetServiceDelegate Protocol Messages*******/
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
