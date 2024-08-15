using module "..\ORCA.psm1"

class ORCA106 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA106()
    {
        $this.Control="ORCA-106"
        $this.Area=Get-LocalizedString -Key "ORCA106_Area"
        $this.Name=Get-LocalizedString -Key "ORCA106_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA106_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA106_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA106_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA106_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA106_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA106_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA106_Link_ManageQuarantine")="https://aka.ms/orca-antispam-docs-6"
            (Get-LocalizedString -Key "ORCA106_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $QuarantineRetentionPeriod = $($Policy.QuarantineRetentionPeriod)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigData=$QuarantineRetentionPeriod
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($QuarantineRetentionPeriod -eq 30)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

        }
    
    }

}
