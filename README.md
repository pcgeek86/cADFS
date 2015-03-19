# cADFS :: Active Directory Federation Services DSC Resources
This repository contains the cADFS PowerShell module, containing Microsoft Windows PowerShell Desired State Configuration (DSC) resources to manage Active Directory Federation Services (ADFS).

# Background
The cADFS module was created in order to configure certain components of the Microsoft Active Directory Federation Services (ADFS) Windows Server role using a declarative syntax, through the Windows PowerShell Desired State Configuration (DSC) feature. Using a declarative syntax for configuration of ADFS components ensures that environments can be version controlled over time, and amongst teams of systems administrators.

# Prerequisites
In order to utilize the DSC resources in the cADFS PowerShell module, you will need to ensure that your managed endpoints are using the February 2015 Preview of the Windows Management Framework (WMF) Core package, or later. The reason that this is required, is because the DSC resources provided by cADFS are developed using PowerShell Classes. Building DSC resources using PowerShell Classes was first supported in the WMF 5.0 February 2015 Preview.

# Installation
To install the cADFS PowerShell module, download it and unzip it to `$env:ProgramFiles\WindowsPowerShell\Modules`.

# Author
The author of this module is Trevor Sullivan. You can follow Trevor on Twitter [@pcgeek86](https://twitter.com/pcgeek86) or on his website / blog at http://trevorsullivan.net.
