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




@implementation AppDelegate

@synthesize wlans;
@synthesize services;
@synthesize fingerprints;
@synthesize serviceBrowser;
@synthesize wlantv= _wlantv;
@synthesize servicesTV = _servicesTV;
@synthesize fingerprintTV = _fingerprintTV;
@synthesize persistentStoreCoordinator = __persistentStoreCoordinator;
@synthesize managedObjectModel = __managedObjectModel;
@synthesize managedObjectContext = __managedObjectContext;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Initialize Sniffer, ServiceBrowser
    ps = [PcapSniffer pcapSniffer];
    serviceBrowser = [[NSNetServiceBrowser alloc] init];
    
    // Set delegate for service browser to app delegate
    [serviceBrowser setDelegate:self];
    
    // Initialize arrays for table views;
    fingerprints = [NSMutableArray array];
    services = [NSMutableArray array];
    
    //INitialize mainBundle annd create components needed for fingerprinting
    mainBundle = [NSBundle mainBundle];
    NSString* filePath = [mainBundle pathForResource:@"HardwareDB" ofType:@"txt"];
    NSStringEncoding encoding;
    NSError *error;
    fileContents = [[NSString alloc] initWithContentsOfFile: filePath
                                                         usedEncoding:&encoding 
                                                                error:&error ];
   
    
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
/************** Hardware Finger Print***************/
-(NSString*) fingerprintRouter:(NSString*) BSSID{
    
    NSString *vendor;
    NSString *macaddress;
    

    //Clean up the original MAC Address. I only need the first 6 digits
    if ( [BSSID length] > 16 )
    {
        macaddress = [BSSID substringToIndex:[BSSID length] - 9];
    }


    NSRange range = NSMakeRange(2,1);
    NSString *clean1 = [macaddress stringByReplacingCharactersInRange:range withString:@""];

    NSRange range2 = NSMakeRange(4,1);
    NSString *cleanedmac = [clean1 stringByReplacingCharactersInRange:range2 withString:@""];
    
    if(fileContents != nil)
    {
        //Putting each line in an array
        lines = [fileContents componentsSeparatedByString:@"\n"];
        
        //Searching throgh each line in the HardwareDB file.
        NSString *temps;
        
        for (NSString *s in lines) {
            temps = s;
            
            if([temps hasPrefix:cleanedmac])
            {
                //Chopping off the MAC address to show the only the vendor
                vendor = [temps substringFromIndex:7];
            }
            
            
        }
        
    }
   
    
    if(vendor == nil)
    {
        vendor = @"Hardware Vendor Not Found in Database!";
    }
    
    
    return vendor;
}
/**************************************************/

/*****************Scan Action *********************/
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
    NSEnumerator* e = [wlans objectEnumerator];
    id obj = [e nextObject];
    while(obj != nil)
    {
        NSDictionary* dict = obj;
        NSString* bssid = [dict objectForKey:@"bssid"];
        NSString* vendorID = [self fingerprintRouter:bssid];
        NSMutableDictionary* fpDict = [NSMutableDictionary dictionary];
        [fpDict setObject:bssid forKey:@"macAddr"];
        [fpDict setObject:vendorID forKey:@"vendor"];
        [fingerprints addObject: fpDict];
        NSLog(@"THe BSSID is: %@ and the Vendor is: %@",bssid,vendorID);
        obj = [e nextObject];
    }
    //message the tableview to update itself;
    [self.wlantv reloadData];
    [self.fingerprintTV reloadData];
}

/******************* End Scan Action *******/
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
                   
                //Find supported Security type and disable fields uneccessary for authentication
                if ([net supportsSecurity:kCWSecurityWEP])
                {
                    
                    // No user name needed for WEP Auth
                    [userName setEnabled:FALSE];
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                       didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                
                    if([net supportsSecurity:kCWSecurityWPAPersonal]){
                       
                        // No User name needed for WPA PSK
                        [userName setEnabled:FALSE];
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                    }
                    if([net supportsSecurity:kCWSecurityWPA2Personal]){
                        //No User name needed for WPA2 Personal
                        [userName setEnabled:FALSE];
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:nil contextInfo:nil];
                    }
                    
                    if([net supportsSecurity:kCWSecurityWPAEnterprise]){
                        
                        [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                           didEndSelector:nil contextInfo:nil];
                    }
                    if([net supportsSecurity:kCWSecurityWPA2Enterprise]){
                        
                  
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                        didEndSelector:nil contextInfo:nil];   
                    }
                if([net supportsSecurity:kCWSecurityNone])
                {
                  
                    [userName setEditable:FALSE];
                    [password setEditable:FALSE];
                    [NSApp beginSheet:joinDialogWindow modalForWindow:window modalDelegate:self
                       didEndSelector:@selector(sheetDidEnd:returnCode:contextInfo:)contextInfo:nil];
                }
        }   
    }
    
}

// The ok button ins the join modal window is clicked to authenticate and connect to a wlan to be scanned
-(IBAction) joinOkClicked:(id)sender{
    
    NSString* itfname = @"en1";
    NSError* err = nil;
    // Create another interface object 
    CWInterface* itf = [CWInterface interfaceWithName:itfname];
    NSMutableDictionary* wlan = [wlans objectAtIndex:[self.wlantv selectedRow]];
    
    //Return a set of networks found by scanning for a network withthe specific SSID
    NSSet* nets = [itf scanForNetworksWithName:[wlan valueForKey:@"ssid"] error:&err];
    
    //Create an enumerator and get the next network object
    NSEnumerator* e = [nets objectEnumerator]; 
    CWNetwork* net = [e nextObject];
    
    // If open authentication then authenticate with no password
    if([net supportsSecurity:kCWSecurityNone] || [net supportsSecurity:kCWSecurityModeOpen])
    {
        [itf associateToNetwork:net password:@"" error:&err];

    }
    
      // If the network is either WEP, WPA PSK, or WPA2 PSK obtain the password and authenticate to network
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
        //Present Error to user if one occurs 
        NSLog(@"Error: %@",[err localizedDescription]);
        [NSApp presentError:err];
        [NSApp stopModal];
        [joinDialogWindow orderOut:sender];
    }
    
    else
    {
        //Association Successful begin scanning for the airport service used By Airport Routers and Time Machines
        [serviceBrowser searchForServicesOfType:@"_airport._tcp" inDomain:@""];
        //Dismiss the authentication Modal WIndow
        [NSApp stopModal];
        //[NSApp endSheet:joinDialogWindow];
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
    if(table == self.fingerprintTV)
    {
        return [wlans count];
    }
    return 0;
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
    if(table == self.fingerprintTV)
    {
        NSDictionary* fp = [[self fingerprints] objectAtIndex:row];
        NSString* identifier = column.identifier;
        return [fp objectForKey:identifier];
    }
    return nil;
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
    if(table == self.fingerprintTV)
    {
        NSMutableDictionary* fingerprint = [self.wlans objectAtIndex:row];
        NSString* identifier = column.identifier;
        [fingerprint setObject:object forKey:identifier];
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
    [serv setObject:servName forKey:@"serviceName"];
    [serv setObject:servType forKey:@"serviceType"];
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
