//
//  main.m
//  MacSnifferGUI
//
//  Created by Quentin  Swain on 11/28/11.
//  Copyright (c) 2011 Washington College. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <PcapSniffer.h>
int main(int argc, char *argv[])
{
    PcapSniffer* ps = [PcapSniffer pcapsniffer];
    return NSApplicationMain(argc, (const char **)argv);
    
}
