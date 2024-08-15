using module "..\ORCA.psm1"

class ORCA121 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA121()
    {
        $this.Control=121
        $this.Area=Get-LocalizedString -Key "ORCA121_Area"
        $this.Name=Get-LocalizedString -Key "ORCA121_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA121_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA121_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA121_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.ObjectType="Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA121_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA121_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA121_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA121_Link_ZHA")="https://aka.ms/orca-zha-docs-2"
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
            $SpamAction = $($Policy.SpamAction)
            $PhishSpamAction =$($Policy.PhishSpamAction)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check requirement of Spam ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="SpamAction"
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($SpamAction -eq "MoveToJmf" -or $SpamAction -eq "Redirect" -or $SpamAction -eq "Delete" -or $SpamAction -eq "Quarantine") 
            {
                $ConfigObject.ConfigData=$SpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.ConfigData=$SpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)

            # Check requirement of Phish ZAP - MoveToJmf, redirect, delete, quarantine

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="PhishSpamAction"
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled=$IsPolicyDisabled
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($PhishSpamAction -eq "MoveToJmf" -or $PhishSpamAction -eq "Redirect" -or $PhishSpamAction -eq "Delete" -or $PhishSpamAction -eq "Quarantine")
            {
                $ConfigObject.ConfigData=$PhishSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.ConfigData=$PhishSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)
    
        }        

    }

}
