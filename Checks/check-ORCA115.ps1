using module "..\ORCA.psm1"

class ORCA115 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA115()
    {
        $this.Control="ORCA-115"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA115_Area"
        $this.Name=Get-LocalizedString -Key "ORCA115_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA115_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA115_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA115_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA115_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA115_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            (Get-LocalizedString -Key "ORCA115_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA115_Link_SetupPolicies")="https://aka.ms/orca-atpp-docs-9"
            (Get-LocalizedString -Key "ORCA115_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-7"
        }   
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        
        ForEach($Policy in ($Config["AntiPhishPolicy"]))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableMailboxIntelligenceProtection = $($Policy.EnableMailboxIntelligenceProtection)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Determine if Mailbox Intelligence Protection is enabled

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableMailboxIntelligenceProtection"
            $ConfigObject.ConfigData=$EnableMailboxIntelligenceProtection
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableMailboxIntelligenceProtection -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")      
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                      
            }

            $this.AddConfig($ConfigObject)

        }

            
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableMailboxIntelligenceProtection"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }


    }

}
