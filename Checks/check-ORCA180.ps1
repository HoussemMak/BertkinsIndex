using module "..\ORCA.psm1"

class ORCA180 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA180()
    {
        $this.Control=180
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA180_Area"
        $this.Name=Get-LocalizedString -Key "ORCA180_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA180_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA180_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA180_Importance"
        $this.ExpandResults=$True
        $this.ObjectType=Get-LocalizedString -Key "ORCA180_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA180_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA180_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA180_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA180_Link_AntispoofProtection")="https://aka.ms/orca-atpp-docs-3"
            (Get-LocalizedString -Key "ORCA180_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
      
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="EnableSpoofIntelligence"
            $ConfigObject.ConfigData=$Policy.EnableSpoofIntelligence
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Fail if Enabled or EnableSpoofIntelligence is not set to true in any policy
            If($Policy.EnableSpoofIntelligence -eq $true)
            {
                # Check objects
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

            }
            else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            $this.AddConfig($ConfigObject)

        }

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableSpoofIntelligence"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }       

    }

}
