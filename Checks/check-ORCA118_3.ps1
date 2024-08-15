using module "..\ORCA.psm1"

class ORCA118_3 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA118_3()
    {
        $this.Control="ORCA-118-3"
        $this.Area=Get-LocalizedString -Key "ORCA118_3_Area"
        $this.Name=Get-LocalizedString -Key "ORCA118_3_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA118_3_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA118_3_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA118_3_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA118_3_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA118_3_DataType"
        $this.ChiValue=[ORCACHI]::Critical
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA118_3_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA118_3_Link_AntiSpamLists")="https://aka.ms/orca-antispam-docs-4"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $AllowedSenderDomains = @($Policy.AllowedSenderDomains)
            $PolicyName = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
    
            # Fail if AllowedSenderDomains is not null
    
            If(($AllowedSenderDomains).Count -gt 0) 
            {
                ForEach($Domain in $AllowedSenderDomains) 
                {

                    # Is this domain an organisation domain?
                    If(@($Config["AcceptedDomains"] | Where-Object {$_.Name -eq $Domain}).Count -gt 0)
                    {
                        # Check objects
                        $ConfigObject = [ORCACheckConfig]::new()
                        $ConfigObject.ConfigItem=$PolicyName
                        $ConfigObject.ConfigData=$Domain
                        $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                        $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                        $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

                        <#
                        
                        Important! This property can be written on pre-set & default policies, do not apply read only here.

                        #>

                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                        $this.AddConfig($ConfigObject) 
                    } 
                }
            } else {
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$PolicyName
                $ConfigObject.ConfigData=Get-LocalizedString -Key "ORCA118_3_AllowedSenderDomainsEmpty"
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                $this.AddConfig($ConfigObject) 
            }
        }        
    }

}
