using module "..\ORCA.psm1"

class ORCA114 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA114()
    {
        $this.Control="ORCA-114"
        $this.Area=Get-LocalizedString -Key "ORCA114_Area"
        $this.Name=Get-LocalizedString -Key "ORCA114_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA114_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA114_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA114_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA114_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA114_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA114_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA114_Link_AntiSpamDocs")="https://aka.ms/orca-antispam-docs-3"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
    
        $CountOfPolicies = ($Config["HostedConnectionFilterPolicy"]).Count
        ForEach($HostedConnectionFilterPolicy in $Config["HostedConnectionFilterPolicy"]) 
        {
            $IsBuiltIn = $false
            $policyname = $($HostedConnectionFilterPolicy.Name)
            $IPAllowList = $($HostedConnectionFilterPolicy.IPAllowList)

            <#
            
            Important! Do not apply read-only to preset policies here.
            
            #>

            # Check if IPAllowList < 0 and return inconclusive for manual checking of size
            If($IPAllowList.Count -gt 0)
            {
                # IP Allow list present
                ForEach($IPAddr in @($IPAllowList)) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.ConfigItem=$policyname
                    $ConfigObject.ConfigData=$IPAddr
                    $ConfigObject.ConfigPolicyGuid=$HostedConnectionFilterPolicy.Guid.ToString()
                    $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$HostedConnectionFilterPolicy.Guid.ToString()].Disabled
                    $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$HostedConnectionFilterPolicy.Guid.ToString()].Applies
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $this.AddConfig($ConfigObject)  
                }
    
            } 
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.ConfigItem=$policyname
                $ConfigObject.ConfigData="No IP detected"
                $ConfigObject.ConfigPolicyGuid=$HostedConnectionFilterPolicy.Guid.ToString()
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$HostedConnectionFilterPolicy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$HostedConnectionFilterPolicy.Guid.ToString()].Applies
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject) 
            }
        }        

    }

}
