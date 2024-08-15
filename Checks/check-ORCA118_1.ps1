using module "..\ORCA.psm1"

class ORCA118_1 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA118_1()
    {
        $this.Control="ORCA-118-1"
        $this.Area=Get-LocalizedString -Key "ORCA118_1_Area"
        $this.Name=Get-LocalizedString -Key "ORCA118_1_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA118_1_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA118_1_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA118_1_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA118_1_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA118_1_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA118_1_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA118_1_Link_UsePolicyLists")="https://aka.ms/orca-antispam-docs-4"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"] ).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
       
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $AllowedSenderDomains = @($Policy.AllowedSenderDomains)


            <#
            
            Important! Do not apply read-only here for preset/default policies as this can be modified
            
            #>
    
            # Fail if AllowedSenderDomains is not null
    
            If(($AllowedSenderDomains).Count -gt 0) 
            {
                ForEach($Domain in $AllowedSenderDomains) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$policyname
                    $ConfigObject.ConfigData=$($Domain.Domain)
                    $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                    $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                    $this.AddConfig($ConfigObject)  
                }
            } 
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$policyname
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                
                $ConfigObject.ConfigData=Get-LocalizedString -Key "ORCA118_1_NoDomainAvailable"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)  
            }
        }        
    }

}
