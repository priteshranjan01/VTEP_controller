# VXLAN Network Configuration

This is an SDN controller application to automatically configure Open vSwitches as VXLAN Tunnel Endpoints (VTEPS).

The steps to configure VXLAN tunnels and then installing forwarding rules is a tedious task. 
This application simplifies this process by providing a single point of control. The network administrator has 
to edit just on JSON file and the controller takes care of the rest.

Goals of this project were: 
- Reduce the configuration efforts for multiple VTEPs to a single controller thereby reducing the configuration time in hours to a few minutes.
- Provide VLAN to VXLAN interoperability to support VLAN-based networks.

Details of the project can be found here: https://sites.google.com/a/ncsu.edu/csc-ece_573_project_group_8/
