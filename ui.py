'''
User Interface
'''
import argparse
version = 0.1
parser = argparse.ArgumentParser(description='Packet Sniffer UI V{0}'.format(version))
parser.add_argument('-ip','--address', help = "Enter ip address manually.", action = "store_true")
parser.add_argument('-p', '--protocol', help = "Enter specific protocol.", action = "store_true")
parser.add_argument('-v','--verbose', action = "count", help = "Display all the process.")
parser.add_argument('-s','--sniffer', action = "count", help = "Apply sniffer")
inst = parser.parse_args()

if inst.verbose:
    print "Entered Verbose"
elif inst.address:
    print "Entered Address"
