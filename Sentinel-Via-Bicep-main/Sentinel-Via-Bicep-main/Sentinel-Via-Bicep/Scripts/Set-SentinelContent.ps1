<#
.SYNOPSIS
    Deploys Microsoft Sentinel Solutions, Analytics Rules, and Workbooks to a specified workspace.

.DESCRIPTION
    Efficiently automates deployment of Sentinel solutions, analytics rules, and workbooks from the Content Hub
    into an Azure Sentinel workspace, with granular deployment/update controls and clear modular structure.

.PARAMETER ResourceGroup
    Name of the Azure Resource Group containing the Sentinel workspace.

.PARAMETER Workspace
    Name of the Sentinel (Log Analytics) workspace.

.PARAMETER Region
    Azure region for deployments.

.PARAMETER Solutions
    Array of solution names to deploy.

.PARAMETER SeveritiesToInclude
    Optional array of rule severities to include (e.g., High, Medium, Low).

.PARAMETER IsGov
    Set to $true for Azure Government cloud.

.PARAMETER ForceSolutionUpdate
    Forces update of already installed solutions.

.PARAMETER ForceRuleDeployment
    Deploys rules for already installed solutions.

.PARAMETER SkipSolutionUpdates
    Skips updating solutions needing updates.

.PARAMETER SkipRuleUpdates
    Skips updating analytics rules needing updates.

.PARAMETER SkipRuleDeployment
    Skips deploying analytics rules entirely.

.PARAMETER SkipWorkbookDeployment
    Skips deploying workbooks entirely.

.PARAMETER ForceWorkbookDeployment
    Forces redeployment of existing workbooks.

.EXAMPLE
    .\Set-SentinelContent.ps1 -ResourceGroup "Security-RG" -Workspace "MySentinelWorkspace" -Region "East US" -Solutions "Microsoft Defender XDR", "Microsoft 365" -SeveritiesToInclude "High", "Medium"
#>

param(
    [Parameter(Mandatory = $true)][string]$ResourceGroup,
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $true)][string]$Region,
    [Parameter(Mandatory = $true)][string[]]$Solutions,
    [Parameter(Mandatory = $false)][string[]]$SeveritiesToInclude = @("High", "Medium", "Low"),
    [Parameter(Mandatory = $false)][bool]$IsGov = $false,
    [Parameter(Mandatory = $false)][switch]$ForceSolutionUpdate,
    [Parameter(Mandatory = $false)][switch]$ForceRuleDeployment,
    [Parameter(Mandatory = $false)][switch]$SkipSolutionUpdates,
    [Parameter(Mandatory = $false)][switch]$SkipRuleUpdates,
    [Parameter(Mandatory = $false)][switch]$SkipRuleDeployment,
    [Parameter(Mandatory = $false)][switch]$SkipWorkbookDeployment,
    [Parameter(Mandatory = $false)][switch]$ForceWorkbookDeployment
)

# Ensure arrays
$Solutions = [array]$Solutions
$SeveritiesToInclude = [array]$SeveritiesToInclude

# Azure authentication & REST header
function Get-AzAuthContext {
    if (-not (Get-AzContext)) {
        if ($IsGov) { Connect-AzAccount -Environment AzureUSGovernment } else { Connect-AzAccount }
    }
    $ctx = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $client = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList $profile
    $token = $client.AcquireAccessToken($ctx.Subscription.TenantId)
    return @{
        Context = $ctx
        SubscriptionId = $ctx.Subscription.Id
        AuthHeader = @{
            'Content-Type' = 'application/json'
            'Authorization' = 'Bearer ' + $token.AccessToken
        }
    }
}

function Get-SentinelApiBaseUri {
    param($SubscriptionId, $ResourceGroup, $Workspace, $IsGov)
    $serverUrl = if ($IsGov) { "https://management.usgovcloudapi.net" } else { "https://management.azure.com" }
    return "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
}

# -- Resource Test Utility --
function Test-SentinelResource {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Solution', 'AnalyticsRule', 'Workbook')]
        [string]$ResourceType,
        [Parameter(Mandatory = $true)] [object]$Resource,
        [Parameter()][array]$InstalledPackages = @(),
        [Parameter()][hashtable]$ExistingRulesByTemplate,
        [Parameter()][hashtable]$ExistingRulesByName,
        [Parameter()][array]$ExistingWorkbooks = @()
    )
    $result = @{
        ResourceType = $ResourceType
        Status = "Unknown"
        DisplayName = ""
        Reason = ""
    }
    switch ($ResourceType) {
        'Solution' {
            $result.DisplayName = $Resource.properties.displayName
            $result.SolutionId = $Resource.name
            $match = $InstalledPackages | Where-Object { $_.properties.displayName -eq $result.DisplayName }
            if ($match) {
                $result.Status = "Installed"
                $result.InstalledPackage = $match[0]
                if ($Resource.properties.version -gt $match[0].properties.version) {
                    $result.Status = "NeedsUpdate"
                    $result.AvailableVersion = $Resource.properties.version
                    $result.InstalledVersion = $match[0].properties.version
                }
            } elseif ($result.DisplayName -match "\[Preview\]|\[Deprecated\]") {
                $result.Status = "Special"
            } else {
                $result.Status = "NotInstalled"
            }
        }
        'AnalyticsRule' {
            $displayName = $Resource.properties.mainTemplate.resources.properties[0].displayName
            $templateName = $Resource.properties.mainTemplate.resources[0].name
            $templateVersion = $Resource.properties.mainTemplate.resources.properties[1].version
            if ($displayName -match "\[Deprecated\]") { $result.Status = "Deprecated" }
            elseif ($ExistingRulesByTemplate.ContainsKey($templateName)) {
                $currentVersion = $ExistingRulesByTemplate[$templateName].properties.templateVersion
                $result.Status = if ($currentVersion -ne $templateVersion) { "NeedsUpdate" } else { "Current" }
            }
            elseif ($ExistingRulesByName.ContainsKey($displayName)) { $result.Status = "NameMatch" }
            else { $result.Status = "Missing" }
            $result.DisplayName = $displayName
            $result.TemplateName = $templateName
            $result.TemplateVersion = $templateVersion
        }
        'Workbook' {
            $displayName = $Resource.properties.displayName
            $templateId = $Resource.properties.contentId
            $templateVersion = $Resource.properties.version
            $result.DisplayName = $displayName
            $existing = $ExistingWorkbooks | Where-Object { $_.properties.contentId -eq $templateId } | Select-Object -First 1
            if ($displayName -match '\[Deprecated\]') { $result.Status = "Deprecated" }
            elseif ($existing) {
                if ($existing.properties.version -ne $templateVersion) { $result.Status = "NeedsUpdate" }
                else { $result.Status = "Current" }
            } elseif ($ExistingWorkbooks | Where-Object { $_.properties.displayName -eq $displayName }) {
                $result.Status = "NameMatch"
            } else {
                $result.Status = "Missing"
            }
        }
    }
    return $result
}

# -- Solution Deployment --
function Deploy-Solutions {
    param(
        [Parameter()][switch]$ForceUpdate,
        [Parameter()][switch]$SkipUpdates,
        [Parameter()][string[]]$Solutions,
        [string]$BaseUri,
        $AuthHeader
    )
    $solutionsApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2024-03-01"
    $installedApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentPackages?api-version=2023-11-01"
    try { $available = (Invoke-RestMethod -Uri $solutionsApi -Headers $AuthHeader).value } catch { return @{} }
    try { $installed = (Invoke-RestMethod -Uri $installedApi -Headers $AuthHeader).value } catch { $installed = @() }
    $toDeploy = @(); $skipped = @(); $special = @(); $failed = @(); $updated = @()
    foreach ($sol in $Solutions) {
        $solution = $available | Where-Object { $_.properties.displayName -eq $sol }
        if (-not $solution) { Write-Warning "Solution '$sol' not found"; continue }
        $status = Test-SentinelResource -ResourceType Solution -Resource $solution -InstalledPackages $installed
        switch ($status.Status) {
            "Installed" { if ($ForceUpdate) { $toDeploy += @{ Solution = $solution; Action = "Update" } } else { $skipped += $status } }
            "NeedsUpdate" { if ($SkipUpdates) { $skipped += $status } else { $toDeploy += @{ Solution = $solution; Action = "Update" } }
            }
            "NotInstalled" { $toDeploy += @{ Solution = $solution; Action = "Install" } }
            "Special" { if ($ForceUpdate) { $toDeploy += @{ Solution = $solution; Action = "Install" } } else { $special += $status } }
        }
    }
    foreach ($item in $toDeploy) {
        $solution = $item.Solution; $action = $item.Action
        $solutionURL = "$BaseUri/providers/Microsoft.SecurityInsights/contentProductPackages/$($solution.name)?api-version=2024-03-01"
        try { $detailed = (Invoke-RestMethod -Uri $solutionURL -Headers $AuthHeader) } catch { $failed += $solution; continue }
        $packagedContent = $detailed.properties.packagedContent
        $installBody = @{
            properties = @{
                parameters = @{
                    workspace = @{ value = $Workspace }
                    'workspace-location' = @{ value = $Region }
                }
                template = $packagedContent
                mode = "Incremental"
            }
        }
        $deploymentName = "allinone-$($solution.name)".Substring(0, [Math]::Min(64, ("allinone-$($solution.name)").Length))
        $serverUrl = $BaseUri.Split("/subscriptions/")[0]
        $installURL = "$serverUrl/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup/providers/Microsoft.Resources/deployments/$deploymentName?api-version=2021-04-01"
        try {
            $jsonBody = $installBody | ConvertTo-Json -Depth 50
            Invoke-RestMethod -Uri $installURL -Method Put -Headers $AuthHeader -Body $jsonBody | Out-Null
        } catch { $failed += $solution; continue }
        if ($action -eq "Update") { $updated += $solution } else { $toDeploy += $solution }
        Start-Sleep -Milliseconds 1000
    }
    return @{
        Deployed = $toDeploy | ForEach-Object { $_.Solution.properties.displayName }
        Updated = $updated | ForEach-Object { $_.properties.displayName }
        Installed = $skipped | ForEach-Object { $_.DisplayName }
        Failed = $failed | ForEach-Object { $_.properties.displayName }
    }
}

# -- Analytics Rule Deployment --
function Deploy-AnalyticalRules {
    param(
        [string[]]$DeployedSolutions,
        [string[]]$SeveritiesToInclude,
        [switch]$SkipUpdates,
        [string]$BaseUri,
        $AuthHeader
    )
    Start-Sleep -Seconds 60
    $solutionsApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2024-03-01"
    $rulesApi = "$BaseUri/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
    $ruleTemplatesApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2023-05-01-preview&`$filter=(properties/contentKind eq 'AnalyticsRule')"
    try {
        $allSolutions = (Invoke-RestMethod -Uri $solutionsApi -Headers $AuthHeader).value
        $existingRules = (Invoke-RestMethod -Uri $rulesApi -Headers $AuthHeader).value
        $ruleTemplates = (Invoke-RestMethod -Uri $ruleTemplatesApi -Headers $AuthHeader).value
    } catch { Write-Error "Failed to fetch rules data"; return }
    $existingByName = @{}; $existingByTemplate = @{}
    foreach ($rule in $existingRules) {
        if ($rule.properties.displayName) { $existingByName[$rule.properties.displayName] = $rule }
        if ($rule.properties.alertRuleTemplateName) { $existingByTemplate[$rule.properties.alertRuleTemplateName] = $rule }
    }
    $deployedIds = @()
    if ($DeployedSolutions) {
        $relevantSolutions = $allSolutions | Where-Object { $_.properties.displayName -in $DeployedSolutions }
        foreach ($solution in $relevantSolutions) {
            if ($solution.properties.contentId) { $deployedIds += $solution.properties.contentId }
            if ($solution.properties.packageId) { $deployedIds += $solution.properties.packageId }
        }
        $rulesToProcess = $ruleTemplates | Where-Object { $deployedIds -contains $_.properties.packageId }
    } else {
        $rulesToProcess = $ruleTemplates
    }
    foreach ($template in $rulesToProcess) {
        $ruleStatus = Test-SentinelResource -ResourceType AnalyticsRule -Resource $template -ExistingRulesByTemplate $existingByTemplate -ExistingRulesByName $existingByName
        if ($SeveritiesToInclude -and ($template.properties.mainTemplate.resources.properties[0].severity -notin $SeveritiesToInclude)) { continue }
        if ($ruleStatus.Status -eq "Current" -or $ruleStatus.Status -eq "NameMatch" -or $ruleStatus.Status -eq "Deprecated") { continue }
        $kind = $template.properties.mainTemplate.resources[0].kind
        $properties = $template.properties.mainTemplate.resources[0].properties; $properties.enabled = $true
        $properties | Add-Member -NotePropertyName "alertRuleTemplateName" -NotePropertyValue $ruleStatus.TemplateName -Force
        $properties | Add-Member -NotePropertyName "templateVersion" -NotePropertyValue $ruleStatus.TemplateVersion -Force
        $ruleId = if ($ruleStatus.Status -eq "NeedsUpdate") { $existingByTemplate[$ruleStatus.TemplateName].name } else { (New-Guid).Guid }
        $alertUri = "$BaseUri/providers/Microsoft.SecurityInsights/alertRules/$ruleId?api-version=2022-12-01-preview"
        $body = @{ kind = $kind; properties = $properties } | ConvertTo-Json -Depth 20
        try { Invoke-RestMethod -Uri $alertUri -Method Put -Headers $AuthHeader -Body $body | Out-Null } catch { continue }
    }
}

# -- Workbook Deployment --
function Deploy-SolutionWorkbooks {
    param(
        [string[]]$DeployedSolutions,
        [switch]$DeployExistingWorkbooks,
        [switch]$SkipUpdates,
        [string]$BaseUri,
        $AuthHeader
    )
    $workbookTemplatesApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2023-05-01-preview&`$filter=(properties/contentKind eq 'Workbook')"
    $workbookMetadataApi = "$BaseUri/providers/Microsoft.SecurityInsights/metadata?api-version=2023-05-01-preview&`$filter=(properties/Kind eq 'Workbook')"
    try {
        $workbookTemplates = (Invoke-RestMethod -Uri $workbookTemplatesApi -Headers $AuthHeader).value
        $workbookMetadata = (Invoke-RestMethod -Uri $workbookMetadataApi -Headers $AuthHeader).value
    } catch { Write-Error "Failed to fetch workbook data"; return }
    $deployedIds = @()
    if ($DeployedSolutions) {
        $solutionsApi = "$BaseUri/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2024-03-01"
        $allSolutions = (Invoke-RestMethod -Uri $solutionsApi -Headers $AuthHeader).value
        $relevantSolutions = $allSolutions | Where-Object { $_.properties.displayName -in $DeployedSolutions }
        foreach ($solution in $relevantSolutions) {
            if ($solution.properties.contentId) { $deployedIds += $solution.properties.contentId }
            if ($solution.properties.packageId) { $deployedIds += $solution.properties.packageId }
        }
        $relevantWorkbooks = $workbookTemplates | Where-Object { $deployedIds -contains $_.properties.packageId }
    } else {
        $relevantWorkbooks = $workbookTemplates
    }
    foreach ($workbookTemplate in $relevantWorkbooks) {
        $status = Test-SentinelResource -ResourceType Workbook -Resource $workbookTemplate -ExistingWorkbooks $workbookMetadata
        if ($status.Status -eq "Current" -and -not $DeployExistingWorkbooks) { continue }
        if ($status.Status -eq "NeedsUpdate" -and $SkipUpdates) { continue }
        if ($status.Status -eq "Deprecated" -or $status.Status -eq "NameMatch") { continue }
        $guid = (New-Guid).Guid
        $workbookDetailUrl = "$BaseUri/providers/Microsoft.SecurityInsights/contentTemplates/$($workbookTemplate.name)?api-version=2023-05-01-preview"
        $workbookDetail = (Invoke-RestMethod -Uri $workbookDetailUrl -Headers $AuthHeader).properties.mainTemplate.resources
        $workbookResource = $workbookDetail | Where-Object type -eq 'Microsoft.Insights/workbooks'
        if (-not $workbookResource) { continue }
        $newWorkbook = $workbookResource | Select-Object * -ExcludeProperty apiVersion, metadata, name
        $newWorkbook | Add-Member -NotePropertyName name -NotePropertyValue $guid
        $newWorkbook | Add-Member -NotePropertyName location -NotePropertyValue $Region -Force
        if (-not ($newWorkbook.PSObject.Properties.Name -contains "kind")) { $newWorkbook | Add-Member -NotePropertyName kind -NotePropertyValue "shared" }
        $workbookPayload = $newWorkbook | ConvertTo-Json -Depth 20
        $serverUrl = $BaseUri.Split("/subscriptions/")[0]
        $workbookCreatePath = "$serverUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$guid?api-version=2022-04-01"
        try { Invoke-RestMethod -Uri $workbookCreatePath -Method Put -Headers $AuthHeader -Body $workbookPayload | Out-Null } catch { continue }
    }
}

# ----- MAIN -----
$auth = Get-AzAuthContext
$SubscriptionId = $auth.SubscriptionId
$AuthHeader = $auth.AuthHeader
$BaseUri = Get-SentinelApiBaseUri -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Workspace $Workspace -IsGov:$IsGov

# Deploy solutions
$deploymentResults = Deploy-Solutions -ForceUpdate:$ForceSolutionUpdate -SkipUpdates:$SkipSolutionUpdates -Solutions $Solutions -BaseUri $BaseUri -AuthHeader $AuthHeader

# Deploy analytics rules
if (-not $SkipRuleDeployment) {
    $solutionsForRules = @()
    if ($deploymentResults.Deployed) { $solutionsForRules += $deploymentResults.Deployed }
    if ($deploymentResults.Updated) { $solutionsForRules += $deploymentResults.Updated }
    if ($ForceRuleDeployment -and $deploymentResults.Installed) { $solutionsForRules += $deploymentResults.Installed }
    if ($solutionsForRules) {
        Deploy-AnalyticalRules -DeployedSolutions $solutionsForRules -SeveritiesToInclude $SeveritiesToInclude -SkipUpdates:$SkipRuleUpdates -BaseUri $BaseUri -AuthHeader $AuthHeader
    }
}

# Deploy workbooks
if (-not $SkipWorkbookDeployment) {
    $solutionsForWorkbooks = @()
    if ($deploymentResults.Deployed) { $solutionsForWorkbooks += $deploymentResults.Deployed }
    if ($deploymentResults.Updated) { $solutionsForWorkbooks += $deploymentResults.Updated }
    if ($ForceWorkbookDeployment -and $deploymentResults.Installed) { $solutionsForWorkbooks += $deploymentResults.Installed }
    if ($solutionsForWorkbooks) {
        Deploy-SolutionWorkbooks -DeployedSolutions $solutionsForWorkbooks -SkipUpdates:$SkipSolutionUpdates -DeployExistingWorkbooks:$ForceWorkbookDeployment -BaseUri $BaseUri -AuthHeader $AuthHeader
    }
}