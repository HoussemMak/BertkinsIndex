using module "..\ORCA.psm1"

class ORCA120_phish : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA120_phish()
    {
        $this.Control="ORCA-120-phish"
        $this.Area=Get-LocalizedString -Key "ORCA120_Area"
        $this.Name=Get-LocalizedString -Key "ORCA120_Name_Phish"
        $this.PassText=Get-LocalizedString -Key "ORCA120_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA120_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA120_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA120_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA120_DataType"
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA120_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA120_Link_ZHA")="https://aka.ms/orca-zha-docs-2"
            (Get-LocalizedString -Key "ORCA120_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $PhishZapEnabled = $($Policy.PhishZapEnabled)
            
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$PhishZapEnabled
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            if($PhishZapEnabled -eq $true) 
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
