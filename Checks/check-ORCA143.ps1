using module "..\ORCA.psm1"

class ORCA143 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA143()
    {
        $this.Control=143
        $this.Area=Get-LocalizedString -Key "ORCA143_Area"
        $this.Name=Get-LocalizedString -Key "ORCA143_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA143_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA143_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA143_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA143_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA143_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA143_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA143_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA143_Link_Settings")="https://aka.ms/orca-antispam-docs-8"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $this.SkipInReport=$True
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count 
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $InlineSafetyTipsEnabled = $($Policy.InlineSafetyTipsEnabled)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="InlineSafetyTipsEnabled"
            $ConfigObject.ConfigData=$InlineSafetyTipsEnabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Fail if InlineSafetyTipsEnabled is not set to true
    
            If($InlineSafetyTipsEnabled -eq $true) 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}
