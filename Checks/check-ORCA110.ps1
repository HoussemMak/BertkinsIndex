using module "..\ORCA.psm1"

class ORCA110 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA110()
    {
        $this.Control="ORCA-110"
        $this.Area=Get-LocalizedString -Key "ORCA110_Area"
        $this.Name=Get-LocalizedString -Key "ORCA110_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA110_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA110_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA110_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA110_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA110_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA110_Link_DefenderPortal")="https://security.microsoft.com/antimalwarev2"
            (Get-LocalizedString -Key "ORCA110_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["MalwareFilterPolicy"]).Count
        $CountOfPolicies = ($global:MalwarePolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableInternalSenderNotifications = $($Policy.EnableInternalSenderAdminNotifications)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$EnableInternalSenderNotifications
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If ($EnableInternalSenderNotifications -eq $False)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)
        }
    }

}
