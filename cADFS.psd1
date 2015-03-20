@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'cADFS.psm1'

    # Version number of this module.
    ModuleVersion = '1.0'

    # ID used to uniquely identify this module
    GUID = '2be44be7-93cf-4c08-8a63-f2a77823ca6b';

    # Author of this module
    Author = 'Trevor Sullivan <pcgeek86@gmail.com>';

    # Company or vendor of this module
    CompanyName = 'Trevor Sullivan <pcgeek86@gmail.com>'

    # Copyright statement for this module
    Copyright = '(c) 2015 Trevor Sullivan. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'This module contains DSC resources that enable management of the Windows Server Active Directory Federation Services (ADFS) role.';

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0';

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = '';

    # Required for DSC to detect PS class-based resources.
    DscResourcesToExport = @(
        'cADFSFarm';
        'cADFSGlobalAuthenticationPolicy';
        'cADFSRelyingPartyTrust';
        );
}  
