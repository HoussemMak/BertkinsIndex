using module "..\ORCA.psm1"

class ORCA142 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA142()
    {
        $this.Control=142
        $this.Area=Get-LocalizedString -Key "ORCA142_Area"
        $this.Name=Get-LocalizedString -Key "ORCA142_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA142_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA142_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA142_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA142_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA142_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA142_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA142_Link_Settings")="https://aka.ms/orca-atpp-docs-6"
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
            $PhishSpamAction = $($Policy.PhishSpamAction)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Fail if PhishSpamAction is not set to Quarantine
    
            If($PhishSpamAction -eq "Quarantine") 
            {
                $ConfigObject.ConfigData=$($PhishSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            else 
            {
                $ConfigObject.ConfigData=$($PhishSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            If($PhishSpamAction -eq "Delete" -or $PhishSpamAction -eq "Redirect")
            {
                $ConfigObject.ConfigData=$($PhishSpamAction)
                
                # For either Delete or Quarantine we should raise an informational
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA142_InfoText" -f $PhishSpamAction
            }   


            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}
