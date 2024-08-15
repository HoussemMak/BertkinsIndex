using module "..\ORCA.psm1"

class ORCA109 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA109()
    {
        $this.Control="ORCA-109"
        $this.Area=Get-LocalizedString -Key "ORCA109_Area"
        $this.Name=Get-LocalizedString -Key "ORCA109_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA109_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA109_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA109_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA109_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA109_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA109_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA109_Link_UseAntiSpamPolicy")="https://aka.ms/orca-antispam-docs-4"
            (Get-LocalizedString -Key "ORCA109_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
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
            $AllowedSenders = $($Policy.AllowedSenders)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            if($null -eq $AllowedSenders)
            {
                $AllowedSenders = "No Sender Detected"
            }

            $ConfigObject.ConfigData = $AllowedSenders
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            <#
            
            Important! Do not apply read-only on preset/default policies here.
            
            #>

            If(($AllowedSenders).Count -eq 0 -or $AllowedSenders -eq "No Sender Detected")
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
