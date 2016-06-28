# OpenC2SDN: Orchestrating SDN controllers via OpenC2
This project contains code that allows SDN controllers to receive and process [OpenC2](http://openc2.org/) actions.


## Actions currently in work:

|user-friendly name | OpenC2 Action | OpenC2 Target | Description|
--------------------|---------------|---------------|----------------------------
|clear static flows | DELETE | 'static flow' |  Remove all static flow rules.|
|delete static flow |  DELETE | 'static flow' | Remove a static flow rule.|
|add static flow  | SET | 'static flow' | Add a static flow rule.|
|list static flows  | GET | 'static flow' | List static flow rules.|
|get uptime | GET | 'uptime' |  Get time since SDN controller startup.|
|list devices | QUERY | 'device' | List devices tracked by the SDN controller.|
|list external links | QUERY | 'external link' | List multi-hop links discovered via BDDP.|
|list internal links | QUERY | 'internal link' | List single-hop links discovered via LLDP.|
|list switches | QUERY | 'datapath' | List SDN switches managed by the controller.|
|list firewall rules | GET | 'firewall rule' | List firewall rules stored in the controller.|
|delete firewall rule | DELETE | 'firewall rule' | Delete a firewall rule.|
|disable firewall | SET | 'firewall state' | Disable the firewall.|
|enable firewall | SET | 'firewall state' | Enable the firewall.|
|get firewall status | GET | 'firewall state' | Get the enable/disable state of the firewall.|
|unblock flow | ALLOW | sdn:flow | Unblock network traffic matching flow parameters.|
|block flow | DENY | sdn:flow | Block network traffic matching flow parameters.|
|unblock arp | ALLOW | sdn:flow | Unblock ARP packets sourced from this MAC.|
|block arp | DENY | sdn:flow | Block ARP packets sourced from this MAC.|
|unblock subnet | ALLOW | sdn:flow | Unblocks traffic to/from the matching IP subnet.|
|block subnet | DENY | sdn:flow | Block traffic to/from the matching IP subnet.|
|unblock mac address | ALLOW | sdn:flow | Unblocks traffic to/from the matching MAC.|
|block mac address | DENY | sdn:flow | Block traffic to/from the matching MAC.|
|unblock ip | ALLOW | sdn:flow | Unblocks traffic to/from the matching IP.|
|block ip | DENY | sdn:flow | Block traffic to/from the matching IP.|
|test connectivity  | QUERY | 'health' | Validate the asset configuration for connectivity.|

