using module "..\ORCA.psm1"

class ORCA220 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA220()
    {
        $this.Control=220
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA220_Area"
        $this.Name=Get-LocalizedString -Key "ORCA220_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA220_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA220_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA220_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA220_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA220_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ObjectType=Get-LocalizedString -Key "ORCA220_ObjectType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA220_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA220_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
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
            $PhishThresholdLevel = $($Policy.PhishThresholdLevel)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$PhishThresholdLevel
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Standard
            If($PhishThresholdLevel -eq 3)  
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Strict
            If($PhishThresholdLevel -eq 4)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,"Fail")
            }

            $this.AddConfig($ConfigObject)
        }
        
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="No Enabled Policies"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }       
    }
}
