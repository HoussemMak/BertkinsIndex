using module "..\ORCA.psm1"

class ORCA141 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA141()
    {
        $this.Control=141
        $this.Area=Get-LocalizedString -Key "ORCA141_Area"
        $this.Name=Get-LocalizedString -Key "ORCA141_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA141_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA141_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA141_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA141_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA141_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA141_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA141_Link_Settings")="https://aka.ms/orca-atpp-docs-6"
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
            $BulkSpamAction = $($Policy.BulkSpamAction)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # For standard Fail if BulkSpamAction is not set to MoveToJmf
    
            If($BulkSpamAction -ne "MoveToJmf") 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            } 
            else 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }

            # For strict Fail if BulkSpamAction is not set to Quarantine

            If($BulkSpamAction -ne "Quarantine") 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)
            } 
            else 
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }

            # For either Delete or Quarantine we should raise an informational

            If($BulkSpamAction -eq "Delete" -or $BulkSpamAction -eq "Redirect")
            {
                $ConfigObject.ConfigData=$($BulkSpamAction)
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA141_InfoText" -f $BulkSpamAction
            }
            
            $this.AddConfig($ConfigObject)

        }        

    }

}
