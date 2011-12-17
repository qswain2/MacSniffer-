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




@synthesize wlans;
@synthesize services;
@synthesize serviceBrowser;
@synthesize wlantv= _wlantv;
@synthesize servicesTV = _servicesTV;

@synthesize persistentStoreCoordinator = __persistentStoreCoordinator;
@synthesize managedObjectModel = __managedObjectModel;
@synthesize managedObjectContext = __managedObjectContext;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    ps = [PcapSniffer pcapSniffer];
    serviceBrowser = [[NSNetServiceBrowser alloc] init];
    [serviceBrowser setDelegate:self];
    
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

/***************** Join Dialog Actions *****/
-(IBAction) joinNetworkAction:(id)sender{
       
   
    //Get the index value of the item currently selected in the table view
    NSInteger selectedIndex = [self.wlantv selectedRow];
        
    //Check for selected Items 
    if(selectedIndex <= -1)
    {
        NSAlert *missingSelection = [[NSAlert alloc]init];
        //Alert user about selecting item in table view
        [missingSelection addButtonWithTitle:@"OK"];
        [missingSelection setMessageText:@"Must select a WLan for association"];
        [missingSelection setInformativeText:@"Must select a WLan for association"];
        return;
    }
        //Create error object
        NSError* err = nil;
        NSMutableDictionary* wlanInfo= [wlans objectAtIndex:selectedIndex];
        // Default wireless interface
        NSString* itfname = @"en1";
        CWInterface* itf = [CWInterface interfaceWithName:itfname];
         
        NSLog(@"Interface Created");
        
        //Ensure that interface is not assoicated to any network
        [itf disassociate];
        
        //Scan for a particular network
        NSSet* networks = [NSSet setWithSet:[itf scanForNetworksWithName:[wlanInfo valueForKey:@"ssid"] error:&err]];
        // If an error occurs report it 
        if(err)
            {
                NSLog(@"Error: %@",[err localizedDescription]);
                [NSApp presentError:err];
            }
        else{
            
            NSLog(@"Number of Networks found: %lu",networks.count);
            NSLog(@"Network Scan complete");
    
            NSLog(@"Attempt Association");
            if (networks.count > 0){
                
                NSEnumerator* netEnum= [networks objectEnumerator];
                CWNetwork* net = [netEnum nextObject];
                   
                //Find supported Security type 
                        
                if ([net supportsSecurity:kCWSecurityWEP])
                {
                    NSLog(@"WEP");
                    // No user name needed for WEP Auth
                    [userName setEnabled:FALSE];
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                       didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                
                    if([net supportsSecurity:kCWSecurityWPAPersonal]){
                        NSLog(@"WPA PSK");
                        // No User name needed for WPA PSK
                        [userName setEnabled:FALSE];
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                    if([net supportsSecurity:kCWSecurityWPA2Personal]){
                        NSLog(@"WPA2 ");
                        //No User name needed for WPA2 Personal
                        [userName setEnabled:FALSE];
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                    
                    if([net supportsSecurity:kCWSecurityWPAEnterprise]){
                            NSLog(@"WPA Enterprise");
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                    if([net supportsSecurity:kCWSecurityWPA2Enterprise]){
                        
                    NSLog(@"WPA2 Enterprise");
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                        didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];   
                    }
                if([net supportsSecurity:kCWSecurityNone])
                {
                    NSLog(@"Open");
                    [userName setEditable:FALSE];
                    [password setEditable:FALSE];
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                       didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                }
                }   
        }
    
}

-(IBAction) joinOkClicked:(id)sender{
    NSString* itfname = @"en1";
    NSError* err = nil;
    CWInterface* itf = [CWInterface interfaceWithName:itfname];
    NSMutableDictionary* wlan = [wlans objectAtIndex:[self.wlantv selectedRow]];
    NSSet* nets = [itf scanForNetworksWithName:[wlan valueForKey:@"ssid"] error:&err];
    NSEnumerator* e = [nets objectEnumerator]; 
    CWNetwork* net = [e nextObject];
     if(!(([net supportsSecurity:kCWSecurityWPAEnterprise]) && ([net supportsSecurity:kCWSecurityWPA2Enterprise]))){
         [itf associateToNetwork:net password:[password stringValue] error:&err];
     }
    else
    {
        /* Method to authenticate to wpa enterprise network. 
        [itf associateToEnterpriseNetwork:net identity:<#(SecIdentityRef)#> username:[userName stringValue] password:[password stringValue] error:&err];
         */
    }
    
    if(err)
    {
        NSLog(@"Error: %@",[err localizedDescription]);
        [NSApp presentError:err];
        [NSApp endSheet:joinDialogWindow];
        [joinDialogWindow orderOut:sender];
    }
    
    else
    {
        NSLog(@"Association Successful");
        [serviceBrowser searchForServicesOfType:@"_airport._tcp" inDomain:@""];
        [NSApp endSheet:joinDialogWindow];
        [joinDialogWindow orderOut:sender]; 
    }
    
}
-(IBAction)joinCancelClicked:(id)sender{
    [NSApp endSheet:joinDialogWindow];
    [joinDialogWindow orderOut:sender];
}
/****************** Join Dialog Actions****/


/****** NSTableView Protocol Messages*******/
- (NSInteger) numberOfRowsInTableView:(NSTableView *)table {
    if(table == self.wlantv)
    {
        return [wlans count];
    }
    
    if(table == self.servicesTV)
    {
        return [services count];
    }
}
-(id) tableView: (NSTableView *)table objectValueForTableColumn: (NSTableColumn *)column
            row: (NSInteger)row{
    if(table == self.wlantv){
    NSDictionary* wlan = [[self wlans] objectAtIndex: row];
    NSString* identifier = column.identifier;
    return [wlan objectForKey:identifier];
    }
    if(table == self.servicesTV)
    {
        NSDictionary* serv = [[self services] objectAtIndex: row];
        NSString* identifier = column.identifier;
        return [serv objectForKey:identifier]; 
    }
}
-(void) tableView: (NSTableView *)table
   setObjectValue: (id)object
   forTableColumn: (NSTableColumn *)column
              row: (NSInteger)row;{
    if(table == self.wlantv){
    NSMutableDictionary* wlan = [self.wlans objectAtIndex:row];
    NSString* identifier = column.identifier;
    [wlan setObject:object forKey:identifier];
    }
    if(table == self.servicesTV)
    {
        NSMutableDictionary* service = [self.services objectAtIndex:row];
        NSString* identifier = column.identifier;
        [service setObject:object forKey:identifier];
    }
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
    
    NSString* servName = aService.name;
    NSString* servType = aService.type;
    NSInteger port = aService.port;
    NSLog(@"Service Name:%@ \n Service type:%@ \n Service Port:%lu \n",servName,servType,port);
    NSMutableDictionary* serv = [NSMutableDictionary dictionary];
    [serv setObject:servName forKey:@"ServiceName"];
    [serv setObject:servType forKey:@"ServiceType"];
    [services addObject:serv];
    [self.servicesTV reloadData];
    
}

-(void)netServiceBrowser:(NSNetServiceBrowser *)aBrowser didRemoveService:(NSNetService *)aService moreComing:(BOOL)more{
    [services removeObject:aService];
    
}
/****** NSNetServiceDelegate Protocol Messages*******/
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {

  
    return NSTerminateNow;
}

@end
