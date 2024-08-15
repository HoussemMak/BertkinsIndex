using module "..\ORCA.psm1"

class ORCA140 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA140()
    {
        $this.Control=140
        $this.Area=Get-LocalizedString -Key "ORCA140_Area"
        $this.Name=Get-LocalizedString -Key "ORCA140_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA140_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA140_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA140_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA140_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA140_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA140_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA140_Link_Settings")="https://aka.ms/orca-atpp-docs-6"
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
            $HighConfidenceSpamAction = $($Policy.HighConfidenceSpamAction)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            
            # Fail if HighConfidenceSpamAction is not set to Quarantine
    
            If($HighConfidenceSpamAction -eq "Quarantine") 
            {
                $ConfigObject.ConfigData=$HighConfidenceSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            } 
            else 
            {
                $ConfigObject.ConfigData=$HighConfidenceSpamAction
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            }

            # For either Delete or Quarantine we should raise an informational
            If($HighConfidenceSpamAction -eq "Delete" -or $HighConfidenceSpamAction -eq "Redirect")
            {
                $ConfigObject.ConfigData=$HighConfidenceSpamAction
    
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,[ORCAResult]::Fail)
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA140_InfoText" -f $HighConfidenceSpamAction
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}
