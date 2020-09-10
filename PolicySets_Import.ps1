<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$ImportPath = $ScriptDir+"\JSON\PolicySets"

function Get-AuthToken
{
	
<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>
	
	[cmdletbinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		$User
	)
	
	$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
	
	$tenant = $userUpn.Host
	
	Write-Host "Checking for AzureAD module..."
	
	$AadModule = Get-Module -Name "AzureAD" -ListAvailable
	
	if ($AadModule -eq $null)
	{
		
		Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
		$AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
		
	}
	
	if ($AadModule -eq $null)
	{
		write-host
		write-host "AzureAD Powershell module not installed..." -f Red
		write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
		write-host "Script can't continue..." -f Red
		write-host
		exit
	}
	
	# Getting path to ActiveDirectory Assemblies
	# If the module count is greater than 1 find the latest version
	
	if ($AadModule.count -gt 1)
	{
		
		$Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
		
		$aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
		
		# Checking if there are multiple versions of the same module found
		
		if ($AadModule.count -gt 1)
		{
			
			$aadModule = $AadModule | Select-Object -Unique
			
		}
		
		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
		
	}
	else
	{
		
		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
		
	}
	
	[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
	
	[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
	
	$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
	
	$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
	
	$resourceAppIdURI = "https://graph.microsoft.com"
	
	$authority = "https://login.microsoftonline.com/$Tenant"
	
	try
	{
		
		$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
		
		# https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
		# Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
		
		$platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
		
		$userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
		
		$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
		
		# If the accesstoken is valid then create the authentication header
		
		if ($authResult.AccessToken)
		{
			
			# Creating header for Authorization token
			
			$authHeader = @{
				'Content-Type'  = 'application/json'
				'Authorization' = "Bearer " + $authResult.AccessToken
				'ExpiresOn'	    = $authResult.ExpiresOn
			}
			
			return $authHeader
			
		}
		
		else
		{
			
			Write-Host
			Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
			Write-Host
			break
			
		}
		
	}
	
	catch
	{
		
		write-host $_.Exception.Message -f Red
		write-host $_.Exception.ItemName -f Red
		write-host
		break
		
	}
	
}

Function Get-PolicySets()

{

 <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>

    param
    (
        $Name
    )

$graphApiVersion = "Beta"
$DCP_resource = "deviceAppManagement/policySets"
	
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName') -eq ("$Name") }
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
    }
}

Function Update-PolicySetItems()
{
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
    [cmdletbinding()]
    
    param
    (
        $JSON,
        $ID
    )
    
    
	$graphApiVersion = "Beta"
	#$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
	$DCP_resource = "deviceAppManagement/policySets/$ID/update"
    Write-Host $JSON 

    try {
 
        if($JSON -eq "" -or $JSON -eq $null){
        write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red
 
        }
 
         else {
 
          
       $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
       Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
               
        }
 
     }
     
     catch {
 
     $ex = $_.Exception
     $errorResponse = $ex.Response.GetResponseStream()
     $reader = New-Object System.IO.StreamReader($errorResponse)
     $reader.BaseStream.Position = 0
     $reader.DiscardBufferedData()
     $responseBody = $reader.ReadToEnd();
     Write-Host "Response content:`n$responseBody" -f Red
     Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
     write-host
     break
 
     }
	
}

####################################################
####################################################
####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if ($global:authToken)
{
	
	# Setting DateTime to Universal time to work in all timezones
	$DateTime = (Get-Date).ToUniversalTime()
	
	# If the authToken exists checking when it expires
	$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
	
	if ($TokenExpires -le 0)
	{
		
		write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
		write-host
		
		# Defining User Principal Name if not present
		
		if ($User -eq $null -or $User -eq "")
		{
			
			$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
			Write-Host
			
		}
		
		$global:authToken = Get-AuthToken -User $User
		
	}
}

# Authentication doesn't exist, calling Get-AuthToken function

else
{
	
	if ($User -eq $null -or $User -eq "")
	{
		
		$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
		Write-Host
		
	}
	
	# Getting the authorization token
	$global:authToken = Get-AuthToken -User $User
	
}

#endregion

####################################################

####################################################
####################################################

Function Add-PolicySets(){

    <#
    .SYNOPSIS
    This function is used to add an device configuration policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy
    .EXAMPLE
    Add-DeviceConfigurationPolicy -JSON $JSON
    Adds a device configuration policy in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceAppManagement/policySets"
    Write-Verbose "Resource: $DCP_resource"
	


       try {
    
           if($JSON -eq "" -or $JSON -eq $null){
           write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red
    
           }
    
            else {
    
             
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
          Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

           }
    
        }
        
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
   }
    
 ####################################################




Function Get-DeviceConfigurationPolicy(){

    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
        try {
    
            if($Name){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').equals("$Name") }
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
    
        }
    
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }
    
    ####################################################
    
# Replacing quotes for Test-Path
$ImportPath = $ImportPath.replace('"','')

if(!(Test-Path "$ImportPath")){

Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
Write-Host "Script can't continue..." -ForegroundColor Red
Write-Host
break

}

####################################################

Get-ChildItem $ImportPath -filter *.json |
Foreach-object {

				$JSON_Data = Get-Content $_.FullName
				#Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
                $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty Id,createdDateTime,lastModifiedDateTime,Status,ErrorCode
                
                $JSON_PolicySetName = $JSON_Convert.displayName
                $JSON_PolicySetName = $JSON_PolicySetName.replace('"', '')
                
                $JSON_PolicySet = $JSON_Convert | Select-Object -Property * -ExcludeProperty Id,createdDateTime,lastModifiedDateTime,Status,ErrorCode,Items

                $JSON_Output = $JSON_PolicySet | ConvertTo-Json -Depth 5
                
                $JSON_Items = $JSON_Convert | Select-Object -Property items 
                $JSON_ItemsOutput = $JSON_Items.items | ConvertTo-Json -depth 5        
               
                Write-Host "Adding PolicySet:" $JSON_Convert.displayName -ForegroundColor Yellow
                Add-PolicySets -JSON $JSON_Output

                if ($JSON_ItemsOutput -eq $null) 
                
                    {
                        Write-Host "No Items"    
                    }

                else
                
                    {
                        
                       $NewPolicySet = Get-PolicySets -Name $JSON_PolicySetName
                                                                                   
                       $PS_ItemsOutput = $JSON_ItemsOutput | ConvertFrom-Json
                                    
                          foreach ($PS_Item in $PS_ItemsOutput)

                                        {

                                            $PolicysetID = $NewPolicySet.id
                                       
                                            $DeviceConfiguration =  Get-DeviceConfigurationPolicy -name $PS_Item.displayName
                                            
                                            $PS_item.payloadId = $DeviceConfiguration.id

                                            $PS_Item = $PS_Item | ConvertTo-Json -Depth 5
                                       
                                            $StartItems = "`{`"addedPolicySetItems`"`:["
                                            $EndItems = "]}"
                                            $FormatOutput = $StartItems+$PS_Item+$EndItems 
                                    
                                            Write-Host "Adding the following item:" -ForegroundColor Yellow

                                            $UpdatePolicySets = Update-PolicySetItems -JSON $FormatOutput -ID $PolicysetID  
                                                                                
                                        }
                      
                    }
                                      
				
}
