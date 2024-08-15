using module "..\ORCA.psm1"

class ORCA101 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA101()
    {
        $this.Control="ORCA-101"
        $this.Area=Get-LocalizedString -Key "ORCA101_Area"
        $this.Name=Get-LocalizedString -Key "ORCA101_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA101_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA101_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA101_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA101_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA101_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            (Get-LocalizedString -Key "ORCA101_Link_SetHostedContentFilterPolicy")="https://aka.ms/orca-antispam-docs-9"
            (Get-LocalizedString -Key "ORCA101_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
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

            $MarkAsSpamBulkMail = $($Policy.MarkAsSpamBulkMail)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigData=$MarkAsSpamBulkMail
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($MarkAsSpamBulkMail -eq "On")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)               
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

        }    

    }

}
