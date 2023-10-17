# Instructions to setup a magic message portal
## Setup functionality
With this instruction a magic message portal is created between two Raspberry Pi (Rapbian OS), which 
are in separate LANs.

All topics which match "tinkerforge/#" will be bridged to the remote broker by the magic message
portal. Tunneling has priority. As soon as the tunnel connection is lost, the secure bridge is used
instead.

## Setup instruction
Call the script "setup.sh" on two Raspberry Pi >=4 as "initiator" and "listener". With the script a tinkerforge 
linear poti position is bridged between the listener and the initiator. Use the UID of the connected potentiometers 
during the setup (one per raspberry pi).

A NodeRED server is running on both machines. Activate the flow "tinkerforge_linear_motorized_poti_sync.json"
on initiator side. Afterwards to position on the listener side is mirrored to the initiator side.
