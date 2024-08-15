using module "..\ORCA.psm1"

class ORCA139 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA139()
    {
        $this.Control=139
        $this.Area=Get-LocalizedString -Key "ORCA139_Area"
        $this.Name=Get-LocalizedString -Key "ORCA139_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA139_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA139_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA139_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA139_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA139_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA139_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA139_Link_Settings")="https://aka.ms/orca-atpp-docs-6"
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

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$($SpamAction)
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            
            # For standard, this should be MoveToJmf
            If($SpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }

            # For strict, this should be Quarantine
            If($SpamAction -ne "Quarantine") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }

            # For either Delete or Redirect we should raise an informational
            If($SpamAction -eq "Delete" -or $SpamAction -eq "Redirect")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA139_InfoText" -f $SpamAction
            }
            
            $this.AddConfig($ConfigObject)
            
        }        

    }

}
