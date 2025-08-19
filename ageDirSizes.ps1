# BASIC USAGE:
# 1. Open the PowerShell command prompt: "C:\Program Files\PowerShell\7\pwsh.exe" 
# 2. Load the file into the command prompt memory space: . .\ageDirSizes.ps1
# 3. Run the command: Export-EnterpriseDirectorySizesToCsv -portalUrl https://<machine.name.with.domain>:7443/arcgis -user <portal admin user> -password <password> -includeUncPaths true  -outputFile ageDirectories.csv

# REQUIREMENTS:
# Requires PowerShell 7
# PowerShell must be enabled on the remote machine (Enable-PSRemoting)
# The executing user must have local admin privileges on the target machines 

# EXTENDED DESCRIPTION:
# This file has a collection of functions that you can call from PowerShell to get directory size information from components within an ArcGIS Enterprise deployment.
# It interrogates the Esri software to understand the machines on which it runs and  where it keeps its "content". 
# It then uses PowerShell remoting to calculate those directory sizes on the machines on which the directories exist.
# Since ArcGIS Data Store is less forthcoming about the locations of its "content", there are remote registry queries and remote file reads to assist in learning those locations.
# When run successfully, it will output a csv file with all the machines, directories, and their sizes (in bytes).
# The command line will report on its progress through the Enterprise deployment.

# The main function of interest is Export-EnterpriseDirectorySizesToCsv.  Calling this as illustrated in the "basic usage" above will do all this.
# Pay careful attention to the "includeUncPaths" parameter.  Unc paths that have a lot of files can take a very long time to traverse.  If your
# Enterprise might have UNC paths with lots of files, you may with to execute this function first with "includeUncPaths" set to false.  Once you 
# know how long that takes, and you have some basic results, you can run it again with that parameter set to true ... or use the technique below
# for arbitrary directories to interrogate them in isolation.  Note that the main "cost" of traversing the UNC paths is incurred by the file share

# If you do not have a full Enterprise (maybe a non-federated ArcGIS Server or just a remote machine with a directory you'd like to know the size of), 
# you can call individual functions for those specific purposes.  

# For example, you can call Export-ServerDirectorySizesToCsv to just work with an 
# ArcGIS Server (federated or not).  Since that function takes a token, not a username and password, you must first acquire a token with one of the 
# Get-__Token functions.  Get-Token can be used to get a token for a non-federated Server site.  Get-PortalToken and Get-PortalTokenForServer can 
# be used to get a Portal token and then exchange it for a token for the federated ArcGIS Server site you care about.

# Or, if you just wish to target an arbitrary directory on an arbitrary machine, you can use Get-BytesForRemoteDirectory and Export-CustomObjectToCsv

# Please note that this script's functions rely on PowerShell/WinRM remoting.  There are a number of foundational configurations and privileges which
# you may need to investigate if you experience errors related to "Access denied" during execution: 
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7.5

# Author: dkrouk@esri.com
# Original Release Date: July 2025
# Revision: August 2025





$global:referer = "https://remote.dir/"
$global:fileDelimiter = ","
$global:expiration = 1440
$global:assumeFileShareIsWindowsVm = $false 

function Get-Token {
    <# =========================================================================
    .SYNOPSIS
        Generate token
    .DESCRIPTION
        Generate token for Portal or Server
    .PARAMETER Context
        Server context (e.g., https://portal.com:7443/arcgis or https://server.com:6443/arcgis)
    .PARAMETER UserName
        String user name
    .PARAMETER Password
        String user password
    .PARAMETER Referer
        Referer
    .PARAMETER EsriServerType
        PORTAL or GISSERVER
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Target URL')]
        #[Alias('Uri')]
        #[ValidatePattern('^https?://[\w\/\.:-]+[^/]$')]
        [ValidateScript({ $_.OriginalString -match $context_regex })]
        [System.Uri] $Context,

        [Parameter(Mandatory, HelpMessage = 'UserName')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Uname,

        [Parameter(Mandatory, HelpMessage = 'Password')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Pwd,

        [Parameter(Mandatory, HelpMessage = 'PORTAL or GISSERVER')]
        [ValidateNotNullOrEmpty()]
        [System.String] $EsriServerType
    )
    Process {

        Write-Verbose 'Get-Token'

        if ($EsriServerType -eq "PORTAL")
        {
            $uri = '{0}/sharing/rest/generateToken' -f $Context       
        }
        elseif ($EsriServerType -eq "GISSERVER")
        {
            $uri = '{0}/admin/generateToken' -f $Context
        }

        Write-Verbose $uri

        $restParams = @{
            Uri    = $uri
            Method = "POST"
			SkipCertificateCheck = $true
            Body   = @{
                username   = $Uname
                password   = $Pwd
                referer    = $global:referer 
                expiration = $global:expiration 
                f          = 'json'
            }
        }

        try { $response = Invoke-RestMethod @restParams }
        catch { $response = $_.Exception.Response }

        # CHECK FOR ERRORS AND RETURN
        if ( -not $response.token ) {
            # CHECK FOR VALID JSON WITH ERROR DETAILS
            if ( $response.error.details ) {
                if ( $response.error.details.GetType().FullName -eq 'System.Object[]' ) { $details = $response.error.details -join "; " }
                else { $details = $response.error.details }

                $tokens = @($response.error.code, $response.error.message, $details)
                $msg = "Request failed with response:`n`tcode: {0}`n`tmessage: {1}`n`tdetails: {2}" -f $tokens
            }
            elseif ( $response.ReasonPhrase ) { $msg = $response.ReasonPhrase }
            else { $msg = "Request failed with unknown error. Username and/or password may be incorrect." }

            Throw $msg
        }
        else {

            $response

        }
    }
}

function Get-PortalToken {
    <# =========================================================================
    .SYNOPSIS
        Generate token
    .DESCRIPTION
        Generate token for ArcGIS Portal
    .PARAMETER Context
        Portal context (e.g., https://arcgis.com/arcgis)
    .PARAMETER UserName
        String user name
    .PARAMETER Password
        String user password
    .PARAMETER Referer
        Referer

    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Target Portal URL')]
        #[Alias('Uri')]
        #[ValidatePattern('^https?://[\w\/\.:-]+[^/]$')]
        [ValidateScript({ $_.OriginalString -match $context_regex })]
        [System.Uri] $Context,

        [Parameter(Mandatory, HelpMessage = 'UserName')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Uname,

        [Parameter(Mandatory, HelpMessage = 'Password')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Pwd
    )
    Process {

        Write-Verbose 'Get-PortalToken'

        $uri = '{0}/sharing/rest/generateToken' -f $Context
        Write-Verbose $uri 

        $restParams = @{
            Uri    = $uri
            Method = "POST"
			SkipCertificateCheck = $true
            Body   = @{
                username   = $Uname
                password   = $Pwd
                referer    = $global:referer 
                expiration = $global:expiration 
                f          = 'json'
            }
        }

        try { $response = Invoke-RestMethod @restParams }
        catch { $response = $_.Exception.Response }

        # CHECK FOR ERRORS AND RETURN
        if ( -not $response.token ) {
            # CHECK FOR VALID JSON WITH ERROR DETAILS
            if ( $response.error.details ) {
                if ( $response.error.details.GetType().FullName -eq 'System.Object[]' ) { $details = $response.error.details -join "; " }
                else { $details = $response.error.details }

                $tokens = @($response.error.code, $response.error.message, $details)
                $msg = "Request failed with response:`n`tcode: {0}`n`tmessage: {1}`n`tdetails: {2}" -f $tokens
            }
            elseif ( $response.ReasonPhrase ) { $msg = $response.ReasonPhrase }
            else { $msg = "Request failed with unknown error. Username and/or password may be incorrect." }

            Throw $msg
        }
        else {

            $response

        }
    }
}

function Get-PortalTokenForServer {
    <# =========================================================================
    .SYNOPSIS
        Generate token
    .DESCRIPTION
        Use a Portal token to generate a Portal token for a federatedServer
    .PARAMETER Context
        Portal context (e.g., https://portal.com:7443/arcgis)
    .PARAMETER PortalToken
        Portal token
    .PARAMETER Referer
        Referer
    .PARAMETER Server
        Server for which the token will be used (e.g. https://server.com:6443/arcgis)
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Target Portal URL')]
        #[Alias('Uri')]
        #[ValidatePattern('^https?://[\w\/\.:-]+[^/]$')]
        [ValidateScript({ $_.OriginalString -match $context_regex })]
        [System.Uri] $Context,

        [Parameter(Mandatory, HelpMessage = 'PortalToken')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,

        [Parameter(Mandatory, HelpMessage = 'Federated server url to use token with')]
        [System.String] $Server

    )
    Process {

        Write-Verbose 'Get-PortalTokenForServer'

        $uri = '{0}/sharing/rest/generateToken' -f $Context
        Write-Verbose $uri

        $restParams = @{
            Uri    = $uri
            Method = "POST"
			SkipCertificateCheck = $true
            Body   = @{
                token      = $portalToken
                referer    = $global:referer 
                serverURL  = $Server
                expiration = $global:expiration 
                f          = 'json'
            }
        }


        try { $response = Invoke-RestMethod @restParams }
        catch { $response = $_.Exception.Response }

        # CHECK FOR ERRORS AND RETURN
        if ( -not $response.token ) {
            # CHECK FOR VALID JSON WITH ERROR DETAILS
            if ( $response.error.details ) {
                if ( $response.error.details.GetType().FullName -eq 'System.Object[]' ) { $details = $response.error.details -join "; " }
                else { $details = $response.error.details }

                $tokens = @($response.error.code, $response.error.message, $details)
                $msg = "Request failed with response:`n`tcode: {0}`n`tmessage: {1}`n`tdetails: {2}" -f $tokens
            }
            elseif ( $response.ReasonPhrase ) { $msg = $response.ReasonPhrase }
            else { $msg = "Request failed with unknown error. Username and/or password may be incorrect." }

            Throw $msg
        }
        else {

            $response

        }
    }
}

function Get-PortalFederatedServers
{
    <# =========================================================================
    .SYNOPSIS
        Lists Portal's federated server Sites
    .DESCRIPTION
        Lists Portal's federated server Sites
    .PARAMETER Token
        Portal token
    .PARAMETER Referer
        Referer
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Portal token')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,
        [Parameter(Mandatory, HelpMessage = 'Context')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalContext

    )
    Process {

        Write-Verbose 'Get-PortalFederatedServers'

        $uri = '{0}/portaladmin/federation/servers' -f $portalContext
        Write-Verbose $uri

		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
                f = 'json'
                token = $portalToken
            }
        }

        # $headers =
            # @{ 
                # Referer = $Referer
            # }        
        # $body = 
            # @{
                # f = 'json'
                # token = $portalToken
            # }

        # $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -Body $body -SkipCertificateCheck $true
		$response = Invoke-RestMethod @restParams
		
        $response
    }

}
function Get-Machines
{
    <# =========================================================================
    .SYNOPSIS
        List machines in a Portal or Server site
    .DESCRIPTION
        List machines in a Portal or Server site
    .PARAMETER Token
        Portal token
    .PARAMETER Context
        Context like https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis
    .PARAMETER Referer
        Referer
    .PARAMETER EsriServerType
        PORTAL or GISSERVER
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Portal token')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,
        [Parameter(Mandatory, HelpMessage = 'https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Context,
        [Parameter(Mandatory, HelpMessage = 'PORTAL or GISSERVER')]
        [ValidateNotNullOrEmpty()]
        [System.String] $EsriServerType

    )
    Process {
        

        if ($EsriServerType -eq 'PORTAL')
        {
            $uri = '{0}/portaladmin/machines' -f $Context
        }
        elseif ($EsriServerType -eq 'GISSERVER')
        {
            $uri = '{0}/admin/machines' -f $Context
        }

        Write-Verbose $uri
				
		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
                f = 'json'
                token = $portalToken
            }
        }

        # $headers =
            # @{ 
                # Referer = $Referer
            # }        
        # $body = 
            # @{
                # f = 'json'
                # token = $portalToken
            # }

        # $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -Body $body -SkipCertificateCheck $true
		$response = Invoke-RestMethod @restParams

        $response
    }

}

function Get-Directories
{
    <# =========================================================================
    .SYNOPSIS
        List Directories in a Portal or Server site
    .DESCRIPTION
        List Directories in a Portal or Server site
    .PARAMETER Token
        Portal token
    .PARAMETER Context
        Context like https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis
    .PARAMETER Referer
        Referer
    .PARAMETER EsriServerType
        PORTAL or GISSERVER
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Portal token')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,
        [Parameter(Mandatory, HelpMessage = 'https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Context,
        [Parameter(Mandatory, HelpMessage = 'PORTAL or GISSERVER')]
        [ValidateNotNullOrEmpty()]
        [System.String] $EsriServerType

    )
    Process {
        
        if ($EsriServerType -eq 'PORTAL')
        {
            $uri = '{0}/portaladmin/system/directories' -f $Context
        }
        elseif ($EsriServerType -eq 'GISSERVER')
        {
            $uri = '{0}/admin/system/directories' -f $Context
        }

        Write-Verbose $uri

		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
                f = 'json'
                token = $portalToken
            }
        }


        # $headers =
            # @{ 
                # Referer = $Referer
            # }        
        # $body = 
            # @{
                # f = 'json'
                # token = $portalToken
            # }

        # $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -Body $body -SkipCertificateCheck $true

		$response = Invoke-RestMethod @restParams
		
        $response
    }

}

function Get-LogSettings
{
    <# =========================================================================
    .SYNOPSIS
        Get Log Settings in a Portal or Server site
    .DESCRIPTION
        Get Log Settings  in a Portal or Server site
    .PARAMETER Token
        Portal token
    .PARAMETER Context
        Context like https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis
    .PARAMETER EsriServerType
        PORTAL or GISSERVER
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Portal token')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,
        [Parameter(Mandatory, HelpMessage = 'https://f.q.d.n:6443/arcgis or https://f.q.d.n:7443/arcgis')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Context,
        [Parameter(Mandatory, HelpMessage = 'PORTAL or GISSERVER')]
        [ValidateNotNullOrEmpty()]
        [System.String] $EsriServerType

    )
    Process {
        
		
        if ($EsriServerType -eq 'PORTAL')
        {
            $uri = '{0}/portaladmin/logs/settings' -f $Context
        }
        elseif ($EsriServerType -eq 'GISSERVER')
        {
            $uri = '{0}/admin/logs/settings' -f $Context
        }

        Write-Verbose $uri

		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
                f = 'json'
                token = $portalToken
            }
        }

		$response = Invoke-RestMethod @restParams
		
		#Write-Host $response

		# Weirdly, the Portal json and Server json are structured slightly differently
		# This reduces the difference
		if ($EsriServerType -eq 'PORTAL')
        {
            $response
        }
        elseif ($EsriServerType -eq 'GISSERVER')
        {
            $response.settings
        }

    }

}

function Get-Config-Store
{
    <# =========================================================================
    .SYNOPSIS
        Gets config-store for a Server site
    .DESCRIPTION
        Server site Config-Store json
    .PARAMETER Token
        Token
    .PARAMETER Context
        Context like https://f.q.d.n:6443/arcgis 
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Portal token')]
        [ValidateNotNullOrEmpty()]
        [System.String] $portalToken,
        [Parameter(Mandatory, HelpMessage = 'https://f.q.d.n:6443/arcgis' )]
        [ValidateNotNullOrEmpty()]
        [System.String] $Context

    )
    Process {
        
		$uri = '{0}/admin/system/configstore' -f $Context

        Write-Verbose $uri

		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
                f = 'json'
                token = $portalToken
            }
        }

		$response = Invoke-RestMethod @restParams
		
        $response
    }

}

function Get-ManagedDataStores
{
	 <# =========================================================================
    .SYNOPSIS
        Gets an array of managed data stores from a hosting server site
    .DESCRIPTION
        Gets an array of managed data stores from a hosting server site
    .PARAMETER TokenValue
        This is a token which ArcGIS Server will recognize as having admin privileges for the purposes
		of getting this information.  The default strategy would be to get a Portal token for a Portal
		admin user and exchange it for a Server token to the federated (hosting) server.
    .PARAMETER Context
        Context like https://f.q.d.n:6443/arcgis 
    .INPUTS
        None.
    .OUTPUTS
        System.Object.
    ========================================================================= #>
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Context,
        
        [Parameter(Mandatory=$true)]
        [string]$TokenValue
    )	

		$uri = '{0}/admin/data/findItems' -f $Context

        Write-Verbose $uri

		 $restParams = @{
            Uri    = $uri
            Method = "GET"
			SkipCertificateCheck = $true
			Headers = @{ 
                Referer = $global:referer
            }    
            Body   = @{
				managed = 'true'
				types = 'egdb'
                f = 'json'
                token = $TokenValue
            }
        }

		$response = Invoke-RestMethod @restParams
		
		$response 
}

function Get-MachineNamesFromDataStores {
    <#
    .SYNOPSIS
        Extracts all machine names from ArcGIS Data Store JSON configuration.
    
    .DESCRIPTION
        This function parses the JSON structure containing ArcGIS Data Store configurations
        and returns a list of all unique machine names found in the machines arrays.
    
    .PARAMETER JsonContent
        The JSON content as a string or PowerShell object containing the data store configuration.
    
    .PARAMETER FilePath
        Path to a JSON file containing the data store configuration.
    
    .PARAMETER Unique
        Switch to return only unique machine names (default behavior).
    
    .EXAMPLE
        # From JSON string
        $jsonString = Get-Content "datastore-config.json" -Raw
        Get-MachineNamesFromDataStores -JsonContent $jsonString
    
    .EXAMPLE
        # From file path
        Get-MachineNamesFromDataStores -FilePath "C:\config\datastore-config.json"
    
    .EXAMPLE
        # Get all machine names including duplicates
        Get-MachineNamesFromDataStores -FilePath "config.json" -Unique:$false
    
    .OUTPUTS
        System.String[]
        Array of machine names found in the configuration.
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'JsonContent')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'JsonContent', ValueFromPipeline = $true)]
        [object]$JsonContent,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'FilePath')]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$FilePath,
        
        [switch]$Unique = $true
    )
    
    begin {
        $machineNames = @()
    }
    
    process {
        try {
            # Handle different input types
            if ($PSCmdlet.ParameterSetName -eq 'FilePath') {
                Write-Verbose "Reading JSON from file: $FilePath"
                $jsonString = Get-Content -Path $FilePath -Raw -ErrorAction Stop
                $dataStoreConfig = $jsonString | ConvertFrom-Json -ErrorAction Stop
            }
            elseif ($JsonContent -is [string]) {
                Write-Verbose "Converting JSON string to object"
                $dataStoreConfig = $JsonContent | ConvertFrom-Json -ErrorAction Stop
            }
            else {
                Write-Verbose "Using provided PowerShell object"
                $dataStoreConfig = $JsonContent
            }
            
            # Validate the structure has the expected items property
            if (-not $dataStoreConfig.items) {
                throw "JSON structure does not contain expected 'items' property"
            }
            
            Write-Verbose "Processing $($dataStoreConfig.items.Count) data store items"
            
            # Extract machine names from each data store item
            foreach ($item in $dataStoreConfig.items) {
                Write-Verbose "Processing item: $($item.path)"
                
                # Check if the item has machines in its info section
                if ($item.info -and $item.info.machines) {
                    foreach ($machine in $item.info.machines) {
                        if ($machine.name) {
                            $machineNames += $machine.name
                            Write-Verbose "Found machine: $($machine.name)"
                        }
                    }
                }
                else {
                    Write-Verbose "No machines found in item: $($item.path)"
                }
            }
            
            Write-Verbose "Total machine names found: $($machineNames.Count)"
            
            # Return unique names by default, or all names if Unique is false
            if ($Unique) {
                $result = $machineNames | Sort-Object -Unique
                Write-Verbose "Returning $($result.Count) unique machine names"
                return $result
            }
            else {
                Write-Verbose "Returning all $($machineNames.Count) machine names (including duplicates)"
                return $machineNames
            }
        }
        catch {
            Write-Error "Error processing data store configuration: $($_.Exception.Message)"
            return @()
        }
    }
}

function Get-FullyQualifiedMachineNames {
    <#
    .SYNOPSIS
        Accepts an array of machine names and removes any that are
		not qualified (it doesn't know when something is "fully" or 
		"partially" qualified.
    
    .DESCRIPTION
        Accepts an array of machine names and removes any that are
		not qualified (it doesn't know when something is "fully" or 
		"partially" qualified.
    
    .PARAMETER MachineNames 
        Array of machine names
   
    .OUTPUTS
        Array with non-qualified machine names removed
    #>			
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string[]]$MachineNames
    )
    
    process {
        return $MachineNames | Where-Object { $_ -match '\.' }
    }
}

function Get-RemoteFileContent {
    <#
    .SYNOPSIS
    Retrieves the content of a text file from a remote system.
    
    .DESCRIPTION
    This function connects to a remote computer and returns the content of a specified text file as a string.
    Requires PowerShell remoting to be enabled on the target machine and appropriate permissions.
    
    .PARAMETER ComputerName
    The name or IP address of the remote computer.
    
    .PARAMETER FilePath
    The absolute path to the text file on the remote system.
    
    .PARAMETER Credential
    Optional credentials to use for the remote connection. If not specified, current user credentials are used.
    
    .EXAMPLE
    Get-RemoteFileContent -ComputerName "Server01" -FilePath "C:\Logs\application.log"
    
    .EXAMPLE
    $cred = Get-Credential
    Get-RemoteFileContent -ComputerName "192.168.1.100" -FilePath "C:\Config\settings.txt" -Credential $cred
    
    .OUTPUTS
    String containing the file content, or $null if file doesn't exist or access is denied.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        # Build parameters for Invoke-Command
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock = {
                param($Path)
                if (Test-Path -Path $Path -PathType Leaf) {
                    Get-Content -Path $Path -Raw
                } else {
                    throw "File not found: $Path"
                }
            }
            ArgumentList = $FilePath
            ErrorAction = 'Stop'
        }
        
        # Add credentials if provided
        if ($Credential) {
            $invokeParams.Add('Credential', $Credential)
        }
        
        # Execute the remote command and return the content
        $content = Invoke-Command @invokeParams
        return $content
        
    } catch {
        Write-Error "Failed to retrieve file content from $ComputerName`: $($_.Exception.Message)"
        return $null
    }
}

function Get-SoftwareInstallPath {
    <#
    .SYNOPSIS
        Gets the installation directory for a specified software product on a machine.
    
    .DESCRIPTION
        This function searches the Windows Registry to find the installation directory
        for a specified software product on a local or remote machine.
    
    .PARAMETER ComputerName
        The name of the machine to query. Defaults to local machine if not specified.
    
    .PARAMETER ProductName
        The name of the software product to search for. Supports partial matches.
    
    .PARAMETER Credential
        Optional credentials for accessing remote machines.
    
    .EXAMPLE
        Get-SoftwareInstallPath -ComputerName "SERVER01" -ProductName "Microsoft Office"
        
    .EXAMPLE
        Get-SoftwareInstallPath -ProductName "Visual Studio" -ComputerName "WORKSTATION02"
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $true)]
        [string]$ProductName,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        # Registry paths to search for installed software
        $registryPaths = @(
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        $results = @()
        
        # Build scriptblock for remote execution
        $scriptBlock = {
            param($ProductName, $RegistryPaths)
            
            $foundSoftware = @()
            
            foreach ($regPath in $RegistryPaths) {
                try {
                    $uninstallKeys = Get-ChildItem -Path "HKLM:\$regPath" -ErrorAction SilentlyContinue
                    
                    foreach ($key in $uninstallKeys) {
                        try {
                            $app = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                            
                            if ($app.DisplayName -and $app.DisplayName -like "*$ProductName*") {
                                $installPath = $null
                                
                                # Try different common property names for install location
                                if ($app.InstallLocation) {
                                    $installPath = $app.InstallLocation
                                } elseif ($app.InstallDir) {
                                    $installPath = $app.InstallDir
                                } elseif ($app.InstallPath) {
                                    $installPath = $app.InstallPath
                                } elseif ($app.UninstallString) {
                                    # Try to extract path from uninstall string
                                    $uninstallPath = $app.UninstallString -replace '"', ''
                                    if (Test-Path (Split-Path $uninstallPath -Parent)) {
                                        $installPath = Split-Path $uninstallPath -Parent
                                    }
                                }
                                
                                if ($installPath -and (Test-Path $installPath)) {
                                    $foundSoftware += [PSCustomObject]@{
                                        ProductName = $app.DisplayName
                                        Version = $app.DisplayVersion
                                        InstallPath = $installPath.TrimEnd('\')
                                        Publisher = $app.Publisher
                                        InstallDate = $app.InstallDate
                                    }
                                }
                            }
                        }
                        catch {
                            # Skip problematic registry entries
                            continue
                        }
                    }
                }
                catch {
                    Write-Warning "Could not access registry path: HKLM:\$regPath"
                }
            }
            
            return $foundSoftware
        }
        
        # Execute locally or remotely
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq ".") {
            # Local execution
            $results = & $scriptBlock -ProductName $ProductName -RegistryPaths $registryPaths
        }
        else {
            # Remote execution
            $invokeParams = @{
                ComputerName = $ComputerName
                ScriptBlock = $scriptBlock
                ArgumentList = @($ProductName, $registryPaths)
                ErrorAction = 'Stop'
            }
            
            if ($Credential) {
                $invokeParams.Credential = $Credential
            }
            
            $results = Invoke-Command @invokeParams
        }
        
        if ($results) {
            return $results | Sort-Object ProductName
        }
        else {
            Write-Warning "No installation found for '$ProductName' on computer '$ComputerName'"
            return $null
        }
    }
    catch {
        Write-Error "Error querying computer '$ComputerName': $($_.Exception.Message)"
        return $null
    }
}

function Remove-TrailingBackslash {
    <#
    .SYNOPSIS
        Removes a trailing backslash from a string
    
    .DESCRIPTION
        Removes a trailing backslash from a string.  This is useful
		prior to joining to another path (where the path is not resolvable
		on the current machine ... with Path-Join seems to require)
    
    .PARAMETER InputString 
        Input to be cleansed
   
    .OUTPUTS
        Cleansed string
    #>		
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$InputString
    )
    
    process {
        if ($InputString.Length -gt 0 -and $InputString[-1] -eq '\') {
            return $InputString.Substring(0, $InputString.Length - 1)
        }
        return $InputString
    }
}

function Remove-NonPrintableCharacters {
    <#
    .SYNOPSIS
        Removes non-printable characters from a string
    
    .DESCRIPTION
        Removes non-printable characters from a string
    
    .PARAMETER InputString 
        Input to be cleansed
   
    .OUTPUTS
        Cleansed string
    #>		
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$InputString
    )

    Process {
        # Regular expression to match non-printable ASCII characters
        # \x20 is the space character, \x7E is the tilde character
        # [^...] negates the character set, matching anything NOT in the set
        $CleanedString = $InputString -replace '[^\\x20-\\x7E]', ''
        Write-Output $CleanedString
    }
}

function Test-Json {
    <#
    .SYNOPSIS
        Determines whether the input is JSON
    
    .DESCRIPTION
        Determines whether the input is JSON
    
    .PARAMETER JsonString
        Input to be tested
   
    .OUTPUTS
        Returns true if it is json
    #>		
    param([string]$JsonString)
    
    try {
        $JsonString | ConvertFrom-Json | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-UNCPath {
    <#
    .SYNOPSIS
        Tests if a string is a UNC (Universal Naming Convention) path.
    
    .DESCRIPTION
        This function checks if the provided string follows the UNC path format
        (\\server\share or \\server\share\path). It does not verify if the path
        exists or is accessible.
    
    .PARAMETER Path
        The string to test for UNC path format.
    
    .EXAMPLE
        Test-UNCPath "\\server\share"
        Returns: $true
    
    .EXAMPLE
        Test-UNCPath "\\fileserver\documents\folder\file.txt"
        Returns: $true
    
    .EXAMPLE
        Test-UNCPath "C:\Windows\System32"
        Returns: $false
    
    .EXAMPLE
        Test-UNCPath ".\relative\path"
        Returns: $false
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Path
    )
    
    process {
        # Check if the path is null or empty
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $false
        }
        
        # UNC paths must start with exactly two backslashes
        if (-not $Path.StartsWith("\\")) {
            return $false
        }
        
        # Remove the leading \\ for further processing
        $pathWithoutPrefix = $Path.Substring(2)
        
        # UNC path must have at least server\share format
        # Split by backslash and check we have at least 2 parts (server and share)
        $parts = $pathWithoutPrefix.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)
        
        if ($parts.Length -lt 2) {
            return $false
        }
        
        # Server name (first part) cannot be empty
        if ([string]::IsNullOrWhiteSpace($parts[0])) {
            return $false
        }
        
        # Share name (second part) cannot be empty
        if ([string]::IsNullOrWhiteSpace($parts[1])) {
            return $false
        }
        
        # Additional validation: server name should not contain invalid characters
        # Common invalid characters for server names
        $invalidServerChars = @('/', ':', '*', '?', '"', '<', '>', '|')
        foreach ($char in $invalidServerChars) {
            if ($parts[0].Contains($char)) {
                return $false
            }
        }
        
        return $true
    }
}

function Test-LetteredDrivePath {
    <#
    .SYNOPSIS
    Tests whether a string represents a lettered drive path format.
    
    .DESCRIPTION
    Determines if a string follows the pattern of a Windows lettered drive path
    (e.g., "C:", "C:\", "D:\folder", etc.) without checking if the drive actually exists.
    
    .PARAMETER Path
    The string to test for lettered drive path format.
    
    .EXAMPLE
    Test-LetteredDrivePath "C:"
    Returns: $true
    
    .EXAMPLE
    Test-LetteredDrivePath "C:\Windows"
    Returns: $true
    
    .EXAMPLE
    Test-LetteredDrivePath "\\server\share"
    Returns: $false
    
    .EXAMPLE
    Test-LetteredDrivePath "relative\path"
    Returns: $false
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Path
    )
    
    process {
        # Check if the string is null or empty
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $false
        }
        
        # Pattern to match lettered drive paths:
        # ^[A-Za-z]: - Starts with a letter followed by colon
        # (\\.*)?$ - Optionally followed by backslash and any characters
        $drivePattern = '^[A-Za-z]:(\\.*)?$'
        
        return $Path -match $drivePattern
    }
}

function Get-BytesForRemoteDirectory
{
    <#
    .SYNOPSIS
        Uses PowerShell remoting to calculate the size of a directory on a remote machine
    
    .DESCRIPTION
        PowerShell remoting determines the size of a directory on a remote machine, returning
		a custom object with the size in bytes and other metadata.
    
    .PARAMETER Path
        The path on the remote machine which will have its size calculated.
    
    .PARAMETER SiteUrl
        A piece of metadata for the site with which the path is associated.  This is put, as-is,
		in the custom object that it is returned.

    .PARAMETER MachineName
        The name of the machine on which the path exists.

    .PARAMETER PathNote
        A piece of metadata about the path that will be put in the custom object as-is.
	   
    .OUTPUTS
        Returns a custom PowerShell object
    #>	
	
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$SiteUrl,		
		
        [Parameter(Mandatory=$true)]
        [string]$MachineName,

        [Parameter(Mandatory=$false)]
        [string]$PathNote = " "
		
    )

	if (Test-PowerShell7OrBetter)
	{
		#Write-Host "✓ Running on PowerShell 7.x or better!" -ForegroundColor Green
	}
	else
	{
		throw "✗ Running on PowerShell $($PSVersionTable.PSVersion.Major).x (older than 7.0).  Please run with PowerShell 7.x or better.  Exiting." 
	}

	$observationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")

	if (Test-UNCPath -Path $Path)
	{
		if ($global:assumeFileShareIsWindowsVm)
		{
			# ask the file share server
			$fileShareMachineName = Get-MachineNameFromUNC $Path 
			$time = Measure-Command { $bytes = Invoke-Command -ComputerName $fileShareMachineName -ScriptBlock { (Get-ChildItem -Path $using:Path -Recurse -Force | Measure-Object -Property Length -Sum).Sum } }
		}
		else
		{
			# ask the file share client
			$time = Measure-Command { $bytes = Invoke-Command -ComputerName $MachineName -ScriptBlock { (Get-ChildItem -Path $using:Path -Recurse -Force | Measure-Object -Property Length -Sum).Sum } }		
		}
	}
	else
	{
		# when the path is not unc, we ask the machine about its local directory
		$time = Measure-Command { $bytes = Invoke-Command -ComputerName $MachineName -ScriptBlock { (Get-ChildItem -Path $using:Path -Recurse -Force | Measure-Object -Property Length -Sum).Sum } }
	}
	

	$obj = [PSCustomObject]@{
		ObservationTime = $observationTime
		SiteUrl = $SiteUrl
		Path = $Path
		MachineName = $MachineName
		PathNote = $pathNote
		NumberOfBytes = $bytes
		Message = "Size measured in " + $time.TotalMilliseconds + " ms"
	}
	
	return $obj
	
}

function Export-CustomObjectToCsv {
    <#
    .SYNOPSIS
        Writes a custom PowerShell object to a delimited file
    
    .DESCRIPTION
        The file is parameter.  The delimiter is specified as a global variable.  The file will be
		created if it does not exist or appended-to if it already exists.
    
    .PARAMETER Object
        Object whose members should be written to the delimited file.
    
    .PARAMETER FilePath
        The file to which the object members should be written
	   
    .OUTPUTS
        Populates a file.
    #>	
	
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Object,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    # Get all properties from the custom object
    $properties = $Object.PSObject.Properties | Sort-Object Name
    
    # Check if file exists
    $fileExists = Test-Path $FilePath
    
    # Function to format a value for CSV
    function Format-CsvValue {
        param($value)
        
        if ($null -eq $value) {
            return '""'
        }
        
        # Check if it's a number (integer or decimal)
        if ($value -is [int] -or $value -is [long] -or $value -is [short] -or 
            $value -is [byte] -or $value -is [double] -or $value -is [float] -or 
            $value -is [decimal]) {
            return $value.ToString()
        }
        
        # Convert to string and escape double quotes
        $stringValue = $value.ToString()
        $escapedValue = $stringValue -replace '"', '""'
        
        # Always wrap strings in double quotes
        return "`"$escapedValue`""
    }
    
	# if we fail to write to the file, this should be an unhandled exception so that the calling process
	# stops or deals with it.
	if (-not $fileExists) {
		# Create new file with header row
		$headerRow = ($properties.Name | ForEach-Object { "`"$_`"" }) -join $global:fileDelimiter
		$headerRow | Out-File -FilePath $FilePath -Encoding UTF8
	}
	
	# Create data row
	$dataRow = ($properties | ForEach-Object { 
		Format-CsvValue -value $_.Value  
	}) -join $global:fileDelimiter
	
	# Append data row to file
	$dataRow | Out-File -FilePath $FilePath -Append -Encoding UTF8
        
}

function Export-PortalDirectorySizesToCsv {
    <#
    .SYNOPSIS
        Gets all directory sizes in a Portal for ArcGIS (not the entire Enterprise) deployment that are relevant to webgisdr
    
    .DESCRIPTION
        Traverses Portal's "content" directories (inclusive of index, db, etc.) and outputs the directory sizes to a file.
    
    .PARAMETER portalUrl
        The entry point for Portal (https://f.q.d.n:7443/arcgis) that does not require web tier auth
    
    .PARAMETER user
        A Portal member which is a memeber of the admin role and can be issued a token from Portal's  
		sharing API's /generateToken
    
    .PARAMETER password
        The password for that user.
		
	.PARAMETER includeUncPaths
		The calculation of the sizes of directories via UNC paths can be very time consuming.  Use
		this switch to allow it if you have time or skip those directories if you do not.
    
	.PARAMETER outputFile
		The name of a file to create (or append-to) for the output of these command
	   
    .OUTPUTS
        Populates a file and returns a Portal token that can then be used by other functions
		
    #>		
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$portalUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$user,		
		
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$false)]
        [string]$includeUncPaths = $true,

        [Parameter(Mandatory=$true)]
        [string]$outputFile
		
    )

	if (Test-PowerShell7OrBetter)
	{
		#Write-Host "✓ Running on PowerShell 7.x or better!" -ForegroundColor Green
	}
	else
	{
		throw "✗ Running on PowerShell $($PSVersionTable.PSVersion.Major).x (older than 7.0).  Please run with PowerShell 7.x or better.  Exiting." 
	}	
	
	if ($global:assumeFileShareIsWindowsVm)
	{
		Write-Host "Global parameter indicates that file shares are Windows machines ..." -ForeGroundColor Yellow
	}
	else
	{
		Write-Host "Global parameter indicates that file shares are NOT Windows machines ..." -ForeGroundColor Yellow
	}
	
	# Get a token for Portal
	$portalToken = Get-Token -Context $portalUrl -Uname $user -Pwd $password  -EsriServerType "PORTAL"
	$portalTokenValue = $portalToken.token 

	$uncPaths = @{}
	
	# Process Portal itself
	Write-Host "Getting Portal machines ..."
	$portalMachines = Get-Machines -Context $portalUrl -portalToken $portalToken.token  -EsriServerType "PORTAL"
	foreach ($portalMachine in $portalMachines.machines )
	{
		$machineName = $portalMachine.machineName
		Write-Host "Getting directories for $machineName ..."
		$portalDirectories = Get-Directories -Context $portalUrl -portalToken $portalTokenValue  -EsriServerType "PORTAL"
		foreach ($portalDirectory in $portalDirectories.directories)
		{
			$physicalPath = $portalDirectory.physicalPath
			$dirType = $portalDirectory.directoryType
			try
			{
				$isUnc = Test-UNCPath $physicalPath
				if ($isUnc)
				{
					# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
					$uncPaths[$physicalPath] = $dirType
				}
				else 
				{
					if ( Test-LetteredDrivePath $physicalPath)
					{
						Write-Host "Getting size for $physicalPath on $machineName ..."
						#Add-BytesForRemoteDirectory -Path $physicalPath -MachineName $machineName -PathNote $dirType -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile
						$myObj = Get-BytesForRemoteDirectory -Path $physicalPath -SiteUrl $portalUrl -MachineName $machineName -PathNote $dirType
						Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
					}
					else
					{
						if (Test-Json $physicalPath)
						{
							$physicalPathObj = $physicalPath | ConvertFrom-Json
							$connectionString = $physicalPathObj.connectionString
							$isUnc = Test-UNCPath $connectionString
							if ($isUnc)
							{
								# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
								$uncPaths[$physicalPath] = $dirType						
							}
							elseif (Test-LetteredDrivePath $connectionString)
							{
								#Add-BytesForRemoteDirectory -Path $connectionString -MachineName $machineName -PathNote $dirType -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile
								$myObj = Get-BytesForRemoteDirectory -Path $connectionString -SiteUrl $portalUrl -MachineName $machineName -PathNote $dirType
								Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
							}
							else
							{
								# Note in the log that we didn't understand how to deal with this "path"
								throw ("This path was not evaluated because what was extracted from the json was not recognized as a file system path")
								
							}
						}
						else
						{
							# Note in the log that we didn't understand how to deal with this "path"
							throw ("This path was not evaluated because the path was not recognized as a file system path")
						}						
					} # json that had some kind of path
				} # a path that isn't UNC

			}
			catch
			{
				# Exceptions related to directories get recorded in the output file
				$obj = [PSCustomObject]@{
					ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
					SiteUrl = $portalUrl
					Path = $physicalPath
					MachineName = $machineName
					PathNote = "EXCEPTION"
					NumberOfBytes = "NA"
					Message = $_.Exception.Message
				}			
				Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 
				#Add-ErrorForRemoteDirectory -Path $physicalPath -MachineName $machineName -PathNote $pathNote -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile 
			}
		} #foreach portal directory
		
		# log Settings
		try
		{
			$logSettings = Get-LogSettings -Context $portalUrl -portalToken $portalToken.token  -EsriServerType "PORTAL"
			$logDir = $logSettings.logDir
			try
			{
				Write-Host "Getting size for $logDir on $machineName ..."
				$isUnc = Test-UNCPath $logDir
				if ($isUnc)
				{
					# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
					$uncPaths[$logDir] = "LOGS"
				}
				elseif (Test-LetteredDrivePath $logDir)
				{
					#Add-BytesForRemoteDirectory -Path $connectionString -MachineName $machineName -PathNote $dirType -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile
					$myObj = Get-BytesForRemoteDirectory -Path $logDir -SiteUrl $portalUrl -MachineName $machineName -PathNote "LOGS"
					Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
				}
				else
				{
					# Note in the log that we didn't understand how to deal with this "path"
					throw ("This path was not evaluated because it was not a drive letter or UNC path")				
				}
			}			
			catch
			{
				# Exceptions related to directories get recorded in the output file
				$obj = [PSCustomObject]@{
					ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
					SiteUrl = $portalUrl
					Path = $logDir
					MachineName = $machineName
					PathNote = "EXCEPTION"
					NumberOfBytes = "NA"
					Message = $_.Exception.Message
				}			
				Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 			
			}
		}
		catch
		{
			Write-Warning "Unable to get log directory for Portal"
		}
	} #foreach portal machine
	

	
	#return to the hashtable (if it exists)
	if ($includeUncPaths)
	{
		if ($uncPaths -and $uncPaths.Count -gt 0)
		{
			foreach ($key in $uncPaths.Keys)
			{
				try
				{
					Write-Host "Getting size for $key on $machineName ..."
					# for convenience, we use the last machine name from the loop for all UNC analysis (all machines in the site should be pointed to the same UNC locations)
					$myObj = Get-BytesForRemoteDirectory -Path $key -SiteUrl $portalUrl -MachineName $machineName -PathNote $value
					Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 		
				}
				catch
				{
					# Exceptions related to directories get recorded in the output file
					$obj = [PSCustomObject]@{
						ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
						SiteUrl = $portalUrl
						Path = $key
						MachineName = $machineName
						PathNote = "EXCEPTION"
						NumberOfBytes = "NA"
						Message = $_.Exception.Message
					}			
					Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 	
				}
			}
		}
		else
		{
			Write-Warning "Script parameters include UNC analysis but no UNC paths were found for $portalUrl"
		}
	}
	else
	{
		Write-Host "Script parameters exclude UNC paths from analysis for $portalUrl"
	}

	# return Portal's token value
	$portalTokenValue
}

function Export-ServerDirectorySizesToCsv {
    <#
    .SYNOPSIS
        Gets all directory sizes in an ArcGIS Server deployment that are relevant to webgisdr
    
    .DESCRIPTION
        Traverses Server's server directories and config-store and outputs the directory sizes to a file.
		In the case that the site has Managed Data Stores (i.e. its configured with ArcGIS Data Store,
		this function will attempt to get the directory information associated with the Data Store 
		machines by calling the functions specific to that.
    
    .PARAMETER serveradminUrl
        The entry point for Server (https://f.q.d.n:6443/arcgis) that does not require web tier auth
    
    .PARAMETER serverTokenValue
        A token appropriate to the ArcGIS Server site.  There are other functions in this file that allow
		such a token to be generated from native ArcGIS Server credential for from the Portal with which the 
		Server is federated.
    	
	.PARAMETER includeUncPaths
		The calculation of the sizes of directories via UNC paths can be very time consuming.  Use
		this switch to allow it if you have time or skip those directories if you do not.
    
	.PARAMETER outputFile
		The name of a file to create (or append-to) for the output of these command
	
    .OUTPUTS
        Populates a file 
		
    #>			
	
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$serverTokenValue,

        [Parameter(Mandatory=$true)]
        [string]$serveradminUrl,

        [Parameter(Mandatory=$false)]
        [string]$includeUncPaths = $true,

        [Parameter(Mandatory=$true)]
        [string]$outputFile

    )

	Write-Host "Getting machines for site $adminUrl ..."
	$serverMachines = Get-Machines -portalToken $serverTokenValue -Context $serveradminUrl -EsriServerType "GISSERVER"
	$uncPaths = @{}
	foreach ($serverMachine in $serverMachines.machines )
	{
		$machineName = $serverMachine.machineName
		Write-Host "Getting directories for $machineName ..."
		$serverDirectories = Get-Directories -Context $serveradminUrl -portalToken $portalTokenValue  -EsriServerType "GISSERVER"		
		
		foreach ($serverDirectory in $serverDirectories.directories)
		{
			$physicalPath = $serverDirectory.physicalPath
			$dirType = $serverDirectory.directoryType
			try
			{
				$isUnc = Test-UNCPath $physicalPath
				if ($isUnc)
				{
					# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
					$uncPaths[$physicalPath] = $dirType
				}
				else
				{
					if ( Test-LetteredDrivePath $physicalPath)
					{
						Write-Host "Getting size for $physicalPath on $machineName ..."
						$myObj = Get-BytesForRemoteDirectory -Path $physicalPath -SiteUrl $serveradminUrl -MachineName $machineName -PathNote $dirType
						Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
					}
					else
					{
						if (Test-Json $physicalPath)
						{
							$physicalPathObj = $physicalPath | ConvertFrom-Json
							$connectionString = $physicalPathObj.connectionString
							$isUnc = Test-UNCPath $connectionString
							if ($isUnc)
							{
								# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
								$uncPaths[$physicalPath] = $dirType						
							}
							else
							{
								Write-Host "Getting size for $connectionString on $machineName ..."
								#Add-BytesForRemoteDirectory -Path $connectionString -MachineName $machineName -PathNote $dirType -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile
								$myObj = Get-BytesForRemoteDirectory -Path $connectionString -SiteUrl $serveradminUrl -MachineName $machineName -PathNote $dirType
								Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
							}
							else
							{
								# Note in the log that we didn't understand how to deal with this "path"
								throw ("This path was not evaluated because what was extracted from the json was not recognized as a file system path")
								
							}
						}
						else
						{
							# Note in the log that we didn't understand how to deal with this "path"
							throw ("This path was not evaluated because the path was not recognized as a file system path")
						}
					} #json									
				} # path that is not unc
			}
			catch			
			{
				# Exceptions related to directories get recorded in the output file
				$obj = [PSCustomObject]@{
					ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
					SiteUrl = $serveradminUrl
					Path = $physicalPath
					MachineName = $machineName
					PathNote = "EXCEPTION"
					NumberOfBytes = "NA"
					Message = $_.Exception.Message
				}			
				Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 			
			}
		} #foreach directory	

		#config-store
		try
		{
			$cfgStorePath = "UNK"
			$cfgStore = Get-Config-Store -Context $serveradminUrl -portalToken $serverTokenValue
			$cfgStoreType = $cfgStore.type
			if ($cfgStoreType -eq "FILESYSTEM")
			{
				$cfgStorePath = $cfgStore.connectionString
				Write-Host "Getting size for $cfgStorePath on $machineName ..."
				$isUnc = Test-UNCPath $cfgStorePath
				if ($isUnc)
				{
					# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
					$uncPaths[$cfgStorePath] = "CONFIG-STORE"
				}
				else			
				{
					if ( Test-LetteredDrivePath $cfgStorePath)
					{
						Write-Host "Getting size for $physicalPath on $machineName ..."
						$myObj = Get-BytesForRemoteDirectory -Path $cfgStorePath -SiteUrl $serveradminUrl -MachineName $machineName -PathNote "CONFIG-STORE"
						Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
					}
					else
					{
						throw ("This path was not evaluated because it does not appear to be a drive letter or UNC path")
					}
				}
			}
			else
			{
				throw ("This path was not evaluated because it is not categorized as a FILESYSTEM path")
			}
		}
		catch
		{
			# Exceptions related to directories get recorded in the output file
			$obj = [PSCustomObject]@{
				ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
				SiteUrl = $serveradminUrl
				Path = $cfgStorePath
				MachineName = $machineName
				PathNote = "EXCEPTION"
				NumberOfBytes = "NA"
				Message = $_.Exception.Message
			}			
			Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 				
		}
		#config-store 


		# log Settings
		try
		{
			$logSettings = Get-LogSettings -Context $serveradminUrl -portalToken $serverTokenValue  -EsriServerType "GISSERVER"
			$logDir = $logSettings.logDir
			try
			{
				$isUnc = Test-UNCPath $logDir
				if ($isUnc)
				{
					# if the path is unc, we want to measure it once, not once per machine.  So, we track it in a separate list to process outside the machine loop.
					$uncPaths[$logDir] = "LOGS"
				}
				elseif (Test-LetteredDrivePath $logDir)
				{
					#Add-BytesForRemoteDirectory -Path $connectionString -MachineName $machineName -PathNote $dirType -OutputFileDelimiter $fileDelimiter -OutputFile $outputFile
					$myObj = Get-BytesForRemoteDirectory -Path $logDir -SiteUrl $serveradminUrl -MachineName $machineName -PathNote "LOGS"
					Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
				}
				else
				{
					# Note in the log that we didn't understand how to deal with this "path"
					throw ("This path was not evaluated because it was not a drive letter or UNC path")				
				}
			}			
			catch
			{
				# Exceptions related to directories get recorded in the output file
				$obj = [PSCustomObject]@{
					ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
					SiteUrl = $serveradminUrl
					Path = $logDir
					MachineName = $machineName
					PathNote = "EXCEPTION"
					NumberOfBytes = "NA"
					Message = $_.Exception.Message
				}			
				Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 			
			}
		}
		catch
		{
			Write-Warning "Unable to get log directory for Server"
		}
	
		
	} #foreach machine
	
	
	
	
	#return to the hashtable (if it exists)
	if ($includeUncPaths)
	{
		if ($uncPaths -and $uncPaths.Count -gt 0)
		{
			foreach ($key in $uncPaths.Keys)
			{
				try
				{
					Write-Host "Getting size for $key on $machineName ..."
					$value = $uncPaths[$key]
					# for convenience, we use the last machine name from the loop for all UNC analysis (all machines in the site should be pointed to the same UNC locations)
					$myObj = Get-BytesForRemoteDirectory -Path $key -SiteUrl $serveradminUrl -MachineName $machineName -PathNote $value
					Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
				}
				catch
				{
					# Exceptions related to directories get recorded in the output file
					$obj = [PSCustomObject]@{
						ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
						SiteUrl = $serveradminUrl
						Path = $key
						MachineName = $machineName
						PathNote = "EXCEPTION"
						NumberOfBytes = "NA"
						Message = $_.Exception.Message
					}			
					Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 
				}
			}
		}
		else
		{
			Write-Warning "Script parameters include UNC analysis but no UNC paths were found for $serveradminUrl"
		}
	}
	else
	{
		Write-Host "Script parameters exclude UNC paths from analysis for $serveradminUrl"
	}

	# This outer try block will determine if there is a Data Store (if the requests fail, we assume there isn't a Data store
	# associated with this federated server
	try
	{
		$managedStores = Get-ManagedDataStores -Context $serveradminUrl -TokenValue $serverTokenValue
		# Non-Hosting Sites should not have an "items" property in the returned value
		if ($managedStores.items.Count -gt 0)
		{
			
			$machines = Get-MachineNamesFromDataStores -JsonContent $managedStores

			if ($machines -and $machines.Count -gt 0)
			{
				$machines = Get-FullyQualifiedMachineNames -MachineNames $machines
				foreach ($machine in $machines)
				{
					# Now that we have machines associated with an ArcGIS Data Store, any subsequent
					# exceptions relate to our inability to get the directory information (as opposed to it not 
					# being a Hosting Server Site
					Write-Host "Getting Data Store information for $machine ..."
					try
					{
						# Query the registry for installation information about ArcGIS Data Store 
						# This will often return more than one installation record (unclear reasons)
						$installArray = Get-SoftwareInstallPath -ComputerName $machine -ProductName "ArcGIS Data Store"

						if ($installArray -and $installArray.Count -gt 0)
						{
							$installLocation = $installArray[0].InstallPath # We only care to work with one installation record, no matter how many there may be
							$installLocation = Remove-TrailingBackslash -InputString $installLocation 
							
							# This file will tell us where the "content" directories are
							$configFileLocation =  $installLocation + "\etc\arcgis-data-store-config.properties" 

							# We get the file content and extract the data directory information
							$configFileContent = Get-RemoteFileContent -ComputerName $machine -FilePath $configFileLocation
							$ind = $configFileContent.IndexOf("dir.data=")
							if ($ind -ne -1)
							{
								$dsContentDir = $configFileContent.Substring($ind + 9)
								$dsContentDir = $dsContentDir.Replace("\:/",":\") # fix-up Data Store path silliness if it is there.
								$dsContentDir = Remove-TrailingBackslash -InputString $dsContentDir 
								$dsContentDir = Remove-NonPrintableCharacters -InputString $dsContentDir
								
								# Now we test for all the known paths that might exist
								$relativePaths = "\backup", "\pgdata", "\cachestoredata", "\elasticdata", "\graphdata", "\nosqldata", "\ozonedata", "\rabbitmqdata", "\staging", "\temp", "\logs"
								foreach ($relativePath in $relativePaths)
								{
									try
									{
										$p = $dsContentDir + $relativePath 
										Write-Host "Getting directory size for $p on $machine ..."
										$myObj = Get-BytesForRemoteDirectory -SiteUrl $serveradminUrl -Path $p -MachineName $machine -PathNote "DATASTORE"
										Export-CustomObjectToCsv -Object $myObj -FilePath $outputFile 
									}
									catch
									{
										# Exceptions related to directories get recorded in the output file
										$obj = [PSCustomObject]@{
											ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
											SiteUrl = $serveradminUrl
											Path = $p
											MachineName = $machineName
											PathNote = "EXCEPTION"
											NumberOfBytes = "NA"
											Message = $_.Exception.Message
										}			
										Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 
										
									}
								}
							}
							else
							{
								throw "Unable to locate arcgisdatastore directory on $machine"
							}
						}
						else
						{
							throw "Software 'ArcGIS Data Store' not found on $machine"
						}		
					}
					catch
					{
						# Exceptions related get recorded in the output file
						$obj = [PSCustomObject]@{
							ObservationTime = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
							SiteUrl = $serveradminUrl
							Path = " "
							MachineName = $machineName
							PathNote = "EXCEPTION"
							NumberOfBytes = "NA"
							Message = $_.Exception.Message
						}			
						Export-CustomObjectToCsv -Object $obj -FilePath $outputFile 
					}
					
				} # foreach machine
				
			} # if there are machines that can be found in the managed data store results 
		} # we think this is a Hosting Site
		else
		{
			Write-Host "$serveradminUrl is not configured with any managed Data Stores (ArcGIS Data Store)"
		}

	}
	catch
	{
		Write-Warning "In not successfully retrieving managed Data Stores or managed data store machines from the site, the script assumes that $serveradminUrl is not a Hosting Server Site"
	}

}

function Export-EnterpriseDirectorySizesToCsv {
    <#
    .SYNOPSIS
        Gets all directory sizes in an ArcGIS Enterprise deployment that are relevant to webgisdr
    
    .DESCRIPTION
        Traverses Portal's "content" directories (inclusive of index, db, etc.), all federated Servers'
		server directories and config-store(s), and for the Hosting server, the Data Store machines'
		"content" directories.  All of that information is written to a delimited text file.
    
    .PARAMETER portalUrl
        The entry point for Portal (https://f.q.d.n:7443/arcgis) that does not require web tier auth
    
    .PARAMETER user
        A Portal member which is a memeber of the admin role and can be issued a token from Portal's  
		sharing API's /generateToken
    
    .PARAMETER password
        The password for that user.
		
	.PARAMETER includeUncPaths
		The calculation of the sizes of directories via UNC paths can be very time consuming.  Use
		this switch to allow it if you have time or skip those directories if you do not.
    
	.PARAMETER outputFile
		The name of a file to create (or append-to) for the output of these command
	   
    .OUTPUTS
        Populates a file
    #>	
	[CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$portalUrl,
        
        [Parameter(Mandatory=$true)]
        [string]$user,		
		
        [Parameter(Mandatory=$true)]
        [string]$password,

        [Parameter(Mandatory=$false)]
        [string]$includeUncPaths = $true,

        [Parameter(Mandatory=$true)]
        [string]$outputFile
    )
	
	if (Test-PowerShell7OrBetter)
	{
		Write-Host "✓ Running on PowerShell 7.x or better!" -ForegroundColor Green
	}
	else
	{
		throw "✗ Running on PowerShell $($PSVersionTable.PSVersion.Major).x (older than 7.0).  Please run with PowerShell 7.x or better.  Exiting." 
	}
	
	if ($global:assumeFileShareIsWindowsVm)
	{
		Write-Host "Global parameter indicates that file shares are Windows machines ..." -ForeGroundColor Yellow
	}
	else
	{
		Write-Host "Global parameter indicates that file shares are NOT Windows machines ..." -ForeGroundColor Yellow
	}

	
	$portalTokenValue = Export-PortalDirectorySizesToCsv -portalUrl $portalUrl -user $user -password $password -includeUncPaths $includeUncPaths  -outputFile $OutputFile 
	
	Write-Host "Getting Federated Sites ..."
	$federatedSites = Get-PortalFederatedServers -portalToken $portalTokenValue -portalContext $portalUrl 
	foreach ($server in $federatedSites.servers)
	{
		$adminUrl = $server.adminUrl
		
		$serverToken = Get-PortalTokenForServer -context $portalUrl -portalToken $portalTokenValue  -Server $adminUrl
		$serverTokenValue = $serverToken.token

		Export-ServerDirectorySizesToCsv -serverTokenValue $serverTokenValue -serveradminUrl $adminUrl -includeUncPaths $includeUncPaths -outputFile $OutputFile 
			
	}
	
	Write-Host "Process complete" -ForeGroundColor Green

}

function Test-PowerShell7OrBetter {
    <#
    .SYNOPSIS
        Determines whether the current PowerShell session is running PowerShell 7.x or better.
    
    .DESCRIPTION
        This function checks the PowerShell version to determine if it's running on
        PowerShell 7.0 or a newer version. It returns $true for PowerShell 7.x and above,
        and $false for Windows PowerShell 5.x or earlier versions.
    
    .EXAMPLE
        Test-PowerShell7OrBetter
        Returns $true if running on PowerShell 7.0 or later, $false otherwise.
    
    .EXAMPLE
        if (Test-PowerShell7OrBetter) {
            Write-Host "Running on PowerShell 7.x or better!"
        } else {
            Write-Host "Running on an older version of PowerShell"
        }
    
    .OUTPUTS
        System.Boolean
    #>
    
    [CmdletBinding()]
    param()
    
    # Get the current PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    
    # Check if major version is 7 or greater
    if ($psVersion.Major -ge 7) {
        Write-Verbose "PowerShell version $($psVersion.ToString()) detected - PowerShell 7.x or better: TRUE"
        return $true
    } else {
        Write-Verbose "PowerShell version $($psVersion.ToString()) detected - PowerShell 7.x or better: FALSE"
        return $false
    }
}

function Get-MachineNameFromUNC {
    <#
    .SYNOPSIS
    Extracts the machine name from a UNC path.
    
    .DESCRIPTION
    This function takes a UNC path (Universal Naming Convention) and extracts the machine/server name from it.
    Supports both standard UNC paths (\\server\share\path) and administrative shares (\\server\c$\path).
    
    .PARAMETER Path
    The UNC path from which to extract the machine name. Must be a valid UNC path starting with '\\'.
    
    .EXAMPLE
    Get-MachineNameFromUNC -Path "\\SERVER01\SharedFolder\file.txt"
    Returns: SERVER01
    
    .EXAMPLE
    Get-MachineNameFromUNC -Path "\\FILESERVER\c$\Windows\System32"
    Returns: FILESERVER
    
    .EXAMPLE
    $MachineName = Get-MachineNameFromUNC -Path "\\SERVER01\share"
    Returns: SERVER01 (stored in $MachineName)
    
    .EXAMPLE
    Get-MachineNameFromUNC -Path "C:\LocalPath"
    Throws: Path 'C:\LocalPath' is not a valid UNC path. UNC paths must start with '\\'.
    
    .OUTPUTS
    System.String - The machine name extracted from the UNC path
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    process {
        # Remove any trailing whitespace
        $UNCPath = $Path.Trim()
        
        # Validate if it's actually a UNC path - throw error if not
        if (-not $UNCPath.StartsWith("\\")) {
            throw "Path '$UNCPath' is not a valid UNC path. UNC paths must start with '\\'."
        }
        
        # Remove the leading \\
        $PathWithoutPrefix = $UNCPath.Substring(2)
        
        # Check if there's actually a machine name
        if ([string]::IsNullOrWhiteSpace($PathWithoutPrefix)) {
            throw "Path '$UNCPath' does not contain a valid machine name."
        }
        
        # Find the first backslash after the machine name
        $FirstBackslashIndex = $PathWithoutPrefix.IndexOf('\')
        
        if ($FirstBackslashIndex -gt 0) {
            # Extract machine name (everything before the first backslash)
            $MachineName = $PathWithoutPrefix.Substring(0, $FirstBackslashIndex)
        } else {
            # No additional path after machine name (e.g., just "\\SERVER")
            $MachineName = $PathWithoutPrefix
        }
        
        # Validate machine name is not empty
        if ([string]::IsNullOrWhiteSpace($MachineName)) {
            throw "Path '$UNCPath' does not contain a valid machine name."
        }
        
        # Return the machine name
        return $MachineName
    }
}

