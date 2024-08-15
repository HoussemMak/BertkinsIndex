using module "..\ORCA.psm1"

class ORCA104 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA104()
    {
        $this.Control="ORCA-104"
        $this.Area=Get-LocalizedString -Key "ORCA104_Area"
        $this.Name=Get-LocalizedString -Key "ORCA104_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA104_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA104_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA104_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA104_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA104_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA104_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA104_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        # Fail if HighConfidencePhishAction is not set to Quarantine

        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            
            $HighConfidencePhishAction = $($Policy.HighConfidencePhishAction)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$HighConfidencePhishAction
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
    
            If($HighConfidencePhishAction -eq "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            }

            If($HighConfidencePhishAction -eq "Redirect" -or $HighConfidencePhishAction -eq "Delete")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,[ORCAResult]::Fail)
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA104_InfoText" -f $HighConfidencePhishAction
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }        

    }

}
