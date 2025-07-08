<#
.SYNOPSIS
    Assigns a least privileged role to a service principal (or managed identity) by Object ID if not already assigned.

.DESCRIPTION
    This script checks for an Azure AD object (Service Principal, Managed Identity, etc.) by its Object ID and assigns a specified Azure role at the subscription scope if the assignment does not already exist.
    It is intended for use in CI/CD scenarios or manual execution to ensure correct role assignment.

.PARAMETER ObjectId
    The Object ID of the Azure AD entity to assign the role to.

.PARAMETER RoleName
    The name of the Azure Role Definition to assign.

.PARAMETER SubscriptionId
    The subscription ID where the role assignment should be made.

.EXAMPLE
    .\AssignLeastPrivilegedRole.ps1 -ObjectId "011291c1-dd79-4434-940b-e3e27073d347" -RoleName "Azure DevOps Least Privileged Deployment" -SubscriptionId "YourSubIDHere"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ObjectId,

    [Parameter(Mandatory = $true)]
    [string]$RoleName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

function Ensure-Module {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Verbose "Module '$ModuleName' not found. Attempting to install..."
        try {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Verbose "Module '$ModuleName' installed successfully."
        } catch {
            Write-Error "Failed to install required module '$ModuleName'. $_"
            exit 100
        }
    }
}

# Ensure required modules are available
Ensure-Module -ModuleName "Az.Accounts"
Ensure-Module -ModuleName "Az.Resources"

# Make sure user is logged in
if (-not (Get-AzContext)) {
    Write-Error "Not logged in to Azure. Run 'Connect-AzAccount' first."
    exit 101
}

try {
    # Validate the object exists
    $sp = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction Stop

    Write-Host "✅ Found Azure AD object with Object ID: $ObjectId"

    # Check if role assignment already exists
    $existingAssignment = Get-AzRoleAssignment -ObjectId $ObjectId `
        -RoleDefinitionName $RoleName `
        -Scope "/subscriptions/$SubscriptionId" `
        -ErrorAction SilentlyContinue

    if (-not $existingAssignment) {
        Write-Host "📌 No existing assignment found. Creating new role assignment..."
        try {
            New-AzRoleAssignment -ObjectId $ObjectId `
                -RoleDefinitionName $RoleName `
                -Scope "/subscriptions/$SubscriptionId" -ErrorAction Stop
            Write-Host "✅ Role assignment created successfully."
            exit 0
        } catch {
            Write-Error "❌ Failed to create role assignment: $_"
            exit 103
        }
    } else {
        Write-Host "⚠️ Role already assigned. Skipping creation."
        exit 0
    }
}
catch {
    Write-Error "❌ Failed to retrieve Azure AD object or assign role. $_"
    exit 105
}
