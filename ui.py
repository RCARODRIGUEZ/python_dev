'''
User Interface
'''
import argparse

parser = argparse.ArgumentParser(description='Packet Sniffer')
parser.add_argument('-ip','--address', help = "Enter ip address manually.",
                    action = "store_true")
parser.add_argument('-v','--verbose', action = "count", help = "Display all the process.")
inst = parser.parse_args()

if inst.verbose:
    print "Entered Verbose"
elif inst.address:
    print "Entered Address"
