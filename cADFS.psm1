enum Ensure {
    Absent;
    Present;
}

#region DSC Resource: cADFSFarm
function InstallADFSFarm {
    <#
    .Synopsis
    Performs the configuration of the Active Directory Federation Services farm.

    .Parameter
    #>
    [CmdletBinding(DefaultParameterSetName='CertificateThumbprint')]
    param (
        [Parameter(Mandatory = $true)]
        [pscredential] $ServiceCredential,
        [Parameter(Mandatory = $true)]
        [pscredential] $InstallCredential,
        [Parameter(Mandatory = $true, ParameterSetName='CertificateThumbprint')]
        [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true, ParameterSetName='CertificateSubject')]
        [string] $CertificateSubject,
        [Parameter(Mandatory = $true)]
        [string] $DisplayName,
        [Parameter(Mandatory = $true)]
        [string] $ServiceName

    )

    $CmdletName = $PSCmdlet.MyInvocation.MyCommand.Name;

    if ($PSBoundParameters.CertificateSubject) {
        $Certificate = Find-Certificate -Subject $CertificateSubject
        $CertificateThumbprint = $Certificate.Thumbprint
    }

    Write-Verbose -Message ('Entering function {0}' -f $CmdletName);

    Install-AdfsFarm `
        -CertificateThumbprint:$CertificateThumbprint `
        -Credential $installCredential `
        -FederationServiceDisplayName $DisplayName `
        -FederationServiceName $ServiceName `
        -OverwriteConfiguration:$true `
        -ServiceAccountCredential $serviceCredential;    

    Write-Verbose -Message ('Entering function {0}' -f $CmdletName);
}

[DscResource()]
class cADFSFarm {
    <#
    The Ensure property is used to determine if the Active Directory Federation Service (ADFS) should be installed (Present) or not installed (Absent).
    #>
    [DscProperty(Mandatory)]
    [Ensure] $Ensure;

    <#
    The DisplayName property is the name of the Active Directory Federation Service (ADFS) that users will see when they are directed to the authentication page.
    #>
    [DscProperty(Mandatory)]
    [string] $DisplayName;

    <#
    The ServiceName property is the name of the Active Directory Federation Services (ADFS) service. For example: adfs-service.contoso.com.
    #>
    [DscProperty(key)]
    [string] $ServiceName;

    <#
    The CertificateThumbprint property is the thumbprint of the certificate, located in the local computer's certificate store, that will be bound to the 
    Active Directory Federation Service (ADFS) farm.
    #>
    [DscProperty()]
    [string] $CertificateThumbprint;

        <#
    The CertificateSubject property is the subject of the certificate, located in the local computer's certificate store, that will be bound to the 
    Active Directory Federation Service (ADFS) farm. Used when the certificate thumbprint is not known when generating the MOF.
    #>
    [DscProperty()]
    [string] $CertificateSubject;

    <#
    The ServiceCredential property is a PSCredential that represents the username/password that the 
    #>
    [DscProperty(Mandatory)]
    [pscredential] $ServiceCredential;

    <#
    The InstallCredential property is a PSCredential that represents the username/password of an Active Directory user account that is a member of
    the Domain Administrators security group. This account will be used to install Active Directory Federation Services (ADFS).
    #>
    [DscProperty(Mandatory)]
    [pscredential] $InstallCredential;

    [cADFSFarm] Get() {
        
        Write-Verbose -Message 'Starting retrieving ADFS Farm configuration.';

        try {
            $AdfsProperties = Get-AdfsProperties -ErrorAction Stop;
        }
        catch {
            Write-Verbose -Message ('Error occurred while retrieving ADFS properties: {0}' -f $global:Error[0].Exception.Message);
        }

        Write-Verbose -Message 'Finished retrieving ADFS Farm configuration.';
        return $this;
    }

    [System.Boolean] Test() {
        # Assume compliance by default
        $Compliant = $true;


        Write-Verbose -Message 'Testing for presence of Active Directory Federation Services (ADFS) farm.';

        try {
            $Properties = Get-AdfsProperties -ErrorAction Stop;
        }
        catch {
            $Compliant = $false;
            return $Compliant;
        }

        if ($this.Ensure -eq 'Present') {
            Write-Verbose -Message 'Checking for presence of ADFS Farm.';
            if ($this.ServiceName -ne $Properties.HostName) {
                Write-Verbose -Message 'ADFS Service Name doesn''t match the desired state.';
                $Compliant = $false;
            }
        }

        if ($this.Ensure -eq 'Absent') {
            Write-Verbose -Message 'Checking for absence of ADFS Farm.';
            if ($Properties) {
                Write-Verbose -Message
                $Compliant = $false;
            }
        }

        return $Compliant;
    }

    [void] Set() {

        ### If ADFS Farm shoud be present, then go ahead and install it.
        if ($this.Ensure -eq [Ensure]::Present) {
            try{
                $AdfsProperties = Get-AdfsProperties -ErrorAction stop;
            }
            catch {
                $AdfsProperties = $false
            }

            if (!$AdfsProperties) {
                Write-Verbose -Message 'Installing Active Directory Federation Services (ADFS) farm.';
                $AdfsFarm = @{
                    ServiceCredential = $this.ServiceCredential;
                    InstallCredential = $this.InstallCredential;
                    DisplayName = $this.DisplayName;
                    ServiceName = $this.ServiceName;
                };
                
                if ($this.CertificateThumbprint) {
                    $AdfsFarm.Add('CertificateThumbprint',$this.CertificateThumbprint);
                }
                elseif ($this.CertificateSubject) {
                     $AdfsFarm.Add('CertificateSubject',$this.CertificateSubject);
                }

                InstallADFSFarm @AdfsFarm;
            }

            if ($AdfsProperties) {
                Write-Verbose -Message 'Configuring Active Directory Federation Services (ADFS) properties.';
                $AdfsProperties = @{
                    DisplayName = $this.DisplayName;
                    };
                Set-AdfsProperties @AdfsProperties;
            }
        }

        if ($this.Ensure -eq [Ensure]::Absent) {
            ### From the help for Remove-AdfsFarmNode: The Remove-AdfsFarmNode cmdlet is deprecated. Instead, use the Uninstall-WindowsFeature cmdlet.
            Uninstall-WindowsFeature -Name ADFS-Federation;
        }

        return;
    }
}
#endregion

#region DSC Resource: cADFSRelyingPartyTrust
[DscResource()]
class cADFSRelyingPartyTrust {
    ### Determines whether or not the ADFS Relying Party Trust should exist.
    [DscProperty()]
    [Ensure] $Ensure;

    ### The Name property must be unique to each ADFS Relying Party application in a farm.
    [DscProperty(Key)]
    [string] $Name;

    ### The identifiers are used to uniquely identify ADFS Relying Party applications.
    [DscProperty(Mandatory)]
    [string[]] $Identifier;

    ### The Notes property allows you to specify helpful notes to other administrators
    ### to help determine the purpose and configuration behind the Relying Party Trust.
    [DscProperty()]
    [string] $Notes;

    ### Transform rules are optional rules that perform mappings between identity attributes and claims.
    [DscProperty()]
    [string] $IssuanceTransformRules;

    ### Issuance authorization rules allow restriction of access based on user claims.
    ### More information: https://technet.microsoft.com/en-us/library/ee913560.aspx
    [DscProperty()]
    [string] $IssuanceAuthorizationRules = '';

    ### The WS-Federation Endpoint is an optional parameter that specifies the WS-Federation Passive URL for the relying party.
    [DscProperty()]
    [string] $WsFederationEndpoint;

    ### Enabling Relying Party monitoring enables automatic updating of Relying Party metadata from the Federation Metadata URL.
    ### More information: http://blogs.msdn.com/b/card/archive/2010/06/25/using-federation-metadata-to-establish-a-relying-party-trust-in-ad-fs-2-0.aspx
    [DscProperty()]
    [bool] $MonitoringEnabled = $false;

    [DscProperty()]
    [string[]] $ClaimsProviderName;

    ### Specifies which protocol profiles the relying party supports. The acceptable values for this parameter are: SAML, WsFederation, and WsFed-SAML.
    [DscProperty()]
    [string] $ProtocolProfile;

    [cADFSRelyingPartyTrust] Get() {
        $this.CheckDependencies();

        Write-Verbose -Message ('Retrieving the current Relying Party Trust configuration for {0}' -f $this.Name);
        
        $RelyingPartyTrust = $null;
        try {
            $RelyingPartyTrust = Get-AdfsRelyingPartyTrust -Name $this.Name -ErrorAction Stop;
        }
        catch {
        }

        $this.Name = $RelyingPartyTrust.Name;
        $this.IssuanceTransformRules = $RelyingPartyTrust.IssuanceTransformRules;
        $this.IssuanceAuthorizationRules = $RelyingPartyTrust.IssuanceAuthorizationRules;
        $this.ClaimsProviderName = $RelyingPartyTrust.ClaimsProviderName;
        $this.ProtocolProfile = $RelyingPartyTrust.ProtocolProfile;
        $this.MonitoringEnabled = $RelyingPartyTrust.MonitoringEnabled;
        $this.WsFederationEndpoint = $RelyingPartyTrust.WsFedEndpoint;
        $this.Notes = $RelyingPartyTrust.Notes;
        $this.Identifier = $RelyingPartyTrust.Identifier;

        return $this;
    }

    [bool] Test() {
        $this.CheckDependencies();

        ### Assume complaince unless a setting does not match.
        $Compliant = $true;

        $RelyingPartyTrust = $null;
        try {
            ### Retrieve the Relying Party Trust using the ADFS PowerShell commands.
            $RelyingPartyTrust = Get-AdfsRelyingPartyTrust -Name $this.Name -ErrorAction Stop;
            Write-Verbose -Message ('Successfully retrieved Relying Party Trust from ADFS named {0}' -f $this.Name);
        }
        catch {
            Write-Verbose -Message ('Error occurred attempting to retrieve Relying Party Trust with name {0}.' -f $this.Name);
            throw $PSItem;
            return $false;
        }

        #region Setting should be absent
        ### If the setting should be absent, but the Relying Party Trust exists, then the system is non-compliant.
        if ($this.Ensure -eq 'Absent') {
            if ($RelyingPartyTrust) {
                Write-Verbose -Message ('Relying Party Trust exists with name {0}. System is non-compliant.' -f $this.Name);
                $Compliant = $false;
            }
            else {
                Write-Verbose -Message ('Relying Party Trust does not exist with name {0}. System is compliant.' -f $this.Name);
                $Compliant = $true;
            }
            return $Compliant;
        }
        #endregion

        #region Setting should be present
        ### If $this.Ensure -eq 'Present' then the following code will execute
        if (!$RelyingPartyTrust) {
            Write-Verbose -Message ('Relying Party does not exist with name {0}.' -f $this.Name);
            return $false;
        }
        if ($RelyingPartyTrust.IssuanceAuthorizationRules -ne $this.IssuanceAuthorizationRules) {
            Write-Verbose -Message ('The current IssuanceAuthorizationRules property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.IssuanceAuthorizationRules, $this.IssuanceAuthorizationRules);
            $Compliant = $false;
        }
        if (($RelyingPartyTrust.IssuanceTransformRules -replace '\s', '') -ne ($this.IssuanceTransformRules -replace '\s', '')) {
            Write-Verbose -Message ('The current IssuanceTransformRules property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.IssuanceTransformRules.Trim(), $this.IssuanceTransformRules.Trim());
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.ClaimsProviderName -ne $this.ClaimsProviderName) {
            Write-Verbose -Message ('The current ClaimsProviderName property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.ClaimsProviderName, $this.ClaimsProviderName);
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.ProtocolProfile -ne $this.ProtocolProfile) {
            Write-Verbose -Message ('The current ProtocolProfile property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.ProtocolProfile, $this.ProtocolProfile);
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.MonitoringEnabled -ne $this.MonitoringEnabled) {
            Write-Verbose -Message ('The current MonitoringEnabled property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.MonitoringEnabled, $this.MonitoringEnabled);
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.Identifier -ne $this.Identifier) {
            Write-Verbose -Message ('The current Identifier property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.Identifier, $this.Identifier);
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.WsFedEndpoint -ne ([System.Uri]$this.WsFederationEndpoint)) {
            Write-Verbose -Message ('The current WsFederationEndpoint property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.WsFedEndpoint, $this.WsFederationEndpoint);
            $Compliant = $false;
        }
        if ($RelyingPartyTrust.Notes -ne $this.Notes) {
            Write-Verbose -Message ('The current Notes property value ({0}) does not match the desired configuration ({1}).' -f $RelyingPartyTrust.Notes, $this.Notes);
            $Compliant = $false;
        }

        if ($Compliant) {
            Write-Verbose -Message ('ADFS Relying Party ({0}) is compliant' -f $this.Name);
        }
        return $Compliant;
        #endregion
    }

    [void] Set() {
        $this.CheckDependencies();

        ### Build a HashTable of what the configuration settings should look like.
        $RelyingPartyTrust = @{
            Identifier = $this.Identifier;
            IssuanceTransformRules = $this.IssuanceTransformRules;
            ProtocolProfile = $this.ProtocolProfile;
            MonitoringEnabled = $this.MonitoringEnabled;
            WsFedEndpoint = [System.Uri]$this.WsFederationEndpoint;
            Notes = $this.Notes;
            Name = $this.Name;
            };

        ### Add the ClaimsProviderName, only if it was specified by the user.
        if ($this.ClaimsProviderName) {
            $RelyingPartyTrust.Add('ClaimsProviderName', $this.ClaimsProviderName);
        }

        if ($this.IssuanceAuthorizationRules) {
            $RelyingPartyTrust.Add('IssuanceAuthorizationRules', $this.IssuanceAuthorizationRules);
        }

        ### Retrieve the existing Relying Party Configuration
        $CurrentRelyingPartyTrust = $null;
        try {
            $CurrentRelyingPartyTrust = Get-AdfsRelyingPartyTrust -Name $this.Name -ErrorAction Stop;
        }
        catch {
            Write-Verbose -Message 'Error occurred while retrieving Relying Party Trust!';
            throw $PSItem;
            return;
        }

        #region DSC Resource Absent
        if ($this.Ensure -eq 'Absent') {
            if ($CurrentRelyingPartyTrust) {
                Write-Verbose -Message 'Relying Party Trust should be absent, but it exists. Removing it.';
                Remove-AdfsRelyingPartyTrust -TargetRelyingParty $CurrentRelyingPartyTrust -ErrorAction Stop;
            }
            else {
                Write-Verbose -Message 'Relying Party Trust does not exist, so we are already compliant. You should never see this message.';
            }
            return;
        }
        #endregion

        #region DSC Resource Present
        $this.DisplayHashTable($RelyingPartyTrust);
        if (!$CurrentRelyingPartyTrust) {
            ### This code executes if the Relying Party Trust does not exist.
            Write-Verbose -Message ('The ADFS Relying Party Trust ({0}) does not exist. Creating it.' -f $this.Name);
            Add-AdfsRelyingPartyTrust @RelyingPartyTrust;
        }
        else {
            Write-Verbose -Message ('The ADFS Relying Party Trust ({0}) already exists, but its configuration does not match desired state. Updating configuration.' -f $this.Name);
            Set-AdfsRelyingPartyTrust @RelyingPartyTrust -TargetName $RelyingPartyTrust.Name;
        }
        #endregion

        Write-Verbose -Message 'Completed the Set() method in the cADFSRelyingPartyTrust DSC Resource.';
        return;
    }

    ### Helper method to validate that dependencies are met for this DSC Resource.
    [bool] CheckDependencies() {
        Write-Verbose -Message 'Checking ADFS dependencies was invoked.';
        try {
            Get-WindowsFeature -Name ADFS -ErrorAction Stop;
            Get-AdfsProperties -ErrorAction Stop;
        }
        catch {
            Write-Verbose -Message 'Error occurred during ADFS dependency checking!';
            throw $PSItem;
            return $false;
        }

        Write-Verbose -Message 'ADFS dependency checking completed.';
        return $true;
    }

    [void] DisplayHashTable([HashTable] $Input) {
        foreach ($Key in $Input.Keys) {
            Write-Verbose -Message ('{0} :: {1}' -f $Key, $Input[$Key]);
        }
        return;
    }
}
#endregion

#region DSC Resource: cADFSGlobalAuthenticationPolicy
[DscResource()]
class cADFSGlobalAuthenticationPolicy {
    [DscProperty(Key)]
    [string] $Name = 'Policy';
    
    [DscProperty()]
    [bool] $DeviceAuthenticationEnabled = $false;

    [DscProperty()]
    [string[]] $PrimaryExtranetAuthenticationProvider = @('FormsAuthentication');

    [DscProperty()]
    [string[]] $PrimaryIntranetAuthenticationProvider = @('WindowsAuthentication');

    [DscProperty()]
    [string[]] $AdditionalAuthenticationProvider = @();

    [DscProperty()]
    [bool] $WindowsIntegratedFallbackEnabled = $true;

    ### Retrieves the current state of the ADFS Global Authentication Policy.
    [cADFSGlobalAuthenticationPolicy] Get() {
        Write-Verbose -Message 'Starting retrieving configuration for ADFS Global Authentication Policy.';
        $CurrentPolicy = Get-AdfsGlobalAuthenticationPolicy;

        $this.PrimaryExtranetAuthenticationProvider = $CurrentPolicy.PrimaryExtranetAuthenticationProvider;
        $this.PrimaryIntranetAuthenticationProvider = $CurrentPolicy.PrimaryIntranetAuthenticationProvider;
        $this.AdditionalAuthenticationProvider = $CurrentPolicy.AdditionalAuthenticationProvider;
        $this.DeviceAuthenticationEnabled = $CurrentPolicy.DeviceAuthenticationEnabled;

        Write-Verbose -Message 'Finished retrieving configuration for ADFS Global Authentication Policy.';
        return $this;
    }

    ### Tests the validity of the current policy against the 
    [bool] Test() {
        Write-Verbose -Message 'Starting evaluating ADFS Global Authentication Policy against desired state.';

        $CurrentPolicy = Get-AdfsGlobalAuthenticationPolicy;

        ### Assume that the system is complaint, unless one of the specific settings does not match.
        $Compliance = $true;

        ### NOTE: Array comparisons must be done using Compare-Object
        if (Compare-Object -ReferenceObject $this.PrimaryExtranetAuthenticationProvider -DifferenceObject $CurrentPolicy.PrimaryExtranetAuthenticationProvider) {
            Write-Verbose -Message 'Primary Extranet Authentication Provider does not match desired configuration.';
            $Compliance = $false;
        }
        if (Compare-Object -ReferenceObject $this.PrimaryIntranetAuthenticationProvider -DifferenceObject $CurrentPolicy.PrimaryIntranetAuthenticationProvider) {
            Write-Verbose -Message 'Primary Intranet Authentication Provider does not match desired configuration.';
            $Compliance = $false;
        }
        if (Compare-Object -ReferenceObject $this.AdditionalAuthenticationProvider -DifferenceObject $CurrentPolicy.AdditionalAuthenticationProvider) {
            Write-Verbose -Message 'Additional Authentication Provider does not match desired configuration.';
            $Compliance = $false;
        }
        if ($this.DeviceAuthenticationEnabled -ne $CurrentPolicy.DeviceAuthenticationEnabled) {
            Write-Verbose -Message 'Device Authentication setting does not match desired configuration.';
            $Compliance = $false;
        }
        if ($this.WindowsIntegratedFallbackEnabled -ne $CurrentPolicy.WindowsIntegratedFallbackEnabled) {
            Write-Verbose -Message 'Windows Integrated Fallback setting does not match desired configuration.';
            $Compliance = $false;
        }

        if ($Compliance) {
            Write-Verbose -Message 'All ADFS Global Authentication settings match desired configuration.';
            }
        return $Compliance;
    }

    [void] Set() {
        Write-Verbose -Message 'Starting setting ADFS Global Authentication configuration.';
        $GlobalAuthenticationPolicy = @{
            PrimaryExtranetAuthenticationProvider = $this.PrimaryExtranetAuthenticationProvider;
            PrimaryIntranetAuthenticationProvider = $this.PrimaryIntranetAuthenticationProvider;
            AdditionalAuthenticationProvider = $this.AdditionalAuthenticationProvider;
            DeviceAuthenticationEnabled = $this.DeviceAuthenticationEnabled;
            WindowsIntegratedFallbackEnabled = $this.WindowsIntegratedFallbackEnabled;
            };
        Set-AdfsGlobalAuthenticationPolicy @GlobalAuthenticationPolicy;
        Write-Verbose -Message 'Finished setting ADFS Global Authentication configuration.';
    }
}
#endregion

<#
    .SYNOPSIS
    Locates one or more certificates using the passed certificate selector parameters.

    If more than one certificate is found matching the selector criteria, they will be
    returned in order of descending expiration date.

    .PARAMETER Thumbprint
    The thumbprint of the certificate to find.

    .PARAMETER FriendlyName
    The friendly name of the certificate to find.

    .PARAMETER Subject
    The subject of the certificate to find.

    .PARAMETER DNSName
    The subject alternative name of the certificate to export must contain these values.

    .PARAMETER Issuer
    The issuer of the certiicate to find.

    .PARAMETER KeyUsage
    The key usage of the certificate to find must contain these values.

    .PARAMETER EnhancedKeyUsage
    The enhanced key usage of the certificate to find must contain these values.

    .PARAMETER Store
    The Windows Certificate Store Name to search for the certificate in.
    Defaults to 'My'.

    .PARAMETER AllowExpired
    Allows expired certificates to be returned.

#>
function Find-Certificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param
    (
        [Parameter()]
        [String]
        $Thumbprint,

        [Parameter()]
        [String]
        $FriendlyName,

        [Parameter()]
        [String]
        $Subject,

        [Parameter()]
        [String[]]
        $DNSName,

        [Parameter()]
        [String]
        $Issuer,

        [Parameter()]
        [String[]]
        $KeyUsage,

        [Parameter()]
        [String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [String]
        $Store = 'My',

        [Parameter()]
        [Boolean]
        $AllowExpired = $false
    )

    $certPath = Join-Path -Path 'Cert:\LocalMachine' -ChildPath $Store

    if (-not (Test-Path -Path $certPath))
    {
        # The Certificte Path is not valid
        New-InvalidArgumentError `
            -ErrorId 'CannotFindCertificatePath' `
            -ErrorMessage ($LocalizedData.CertificatePathError -f $certPath)
    } # if

    # Assemble the filter to use to select the certificate
    $certFilters = @()
    if ($PSBoundParameters.ContainsKey('Thumbprint'))
    {
        $certFilters += @('($_.Thumbprint -eq $Thumbprint)')
    } # if

    if ($PSBoundParameters.ContainsKey('FriendlyName'))
    {
        $certFilters += @('($_.FriendlyName -eq $FriendlyName)')
    } # if

    if ($PSBoundParameters.ContainsKey('Subject'))
    {
        $certFilters += @('($_.Subject -eq $Subject)')
    } # if

    if ($PSBoundParameters.ContainsKey('Issuer'))
    {
        $certFilters += @('($_.Issuer -eq $Issuer)')
    } # if

    if (-not $AllowExpired)
    {
        $certFilters += @('(((Get-Date) -le $_.NotAfter) -and ((Get-Date) -ge $_.NotBefore))')
    } # if

    if ($PSBoundParameters.ContainsKey('DNSName'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject $_.DNSNameList.Unicode -DifferenceObject $DNSName | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('KeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.Extensions.KeyUsages -split ", ") -DifferenceObject $KeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('EnhancedKeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.EnhancedKeyUsageList.FriendlyName) -DifferenceObject $EnhancedKeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    # Join all the filters together
    $certFilterScript = '(' + ($certFilters -join ' -and ') + ')'

    Write-Verbose -Message ($LocalizedData.SearchingForCertificateUsingFilters `
        -f $store,$certFilterScript)

    $certs = Get-ChildItem -Path $certPath |
        Where-Object -FilterScript ([ScriptBlock]::Create($certFilterScript))

    # Sort the certificates
    if ($certs.count -gt 1)
    {
        $certs = $certs | Sort-Object -Descending -Property 'NotAfter'
    } # if

    return $certs
} # end function Find-Certificate

return;

<#
####### DOESN'T WORK DUE TO BUG #######
####### https://connect.microsoft.com/PowerShell/feedback/details/1191366

Write-Host -Object 'Loading cADFS module';

#region Import DSC Resources
$ResourceList = Get-ChildItem -Path $PSScriptRoot\Resources;

foreach ($Resource in $ResourceList) {
    Write-Verbose -Message ('Loading DSC resource from {0}' -f $Resource.FullName);
    . $Resource.FullName;
}
#endregion

Write-Host -Object 'Finished loading module.';
#>