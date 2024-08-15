using module "..\ORCA.psm1"

class ORCA179 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA179()
    {
        $this.Control=179
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA179_Area"
        $this.Name=Get-LocalizedString -Key "ORCA179_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA179_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA179_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA179_Importance"
        $this.ExpandResults=$True
        $this.ChiValue=[ORCACHI]::High
        $this.ItemName=Get-LocalizedString -Key "ORCA179_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA179_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA179_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA179_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $Enabled = $False
        $PolicyCount = 0
      
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableForInternalSenders = $($Policy.EnableForInternalSenders)

            $PolicyName = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            if(!$IsPolicyDisabled)
            {
                $PolicyCount++
            }
            

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$($PolicyName)
            $ConfigObject.ConfigData=$EnableForInternalSenders
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Determine if MDO link tracking is on for this safelinks policy
            If($EnableForInternalSenders -eq $true) 
            {
                $Enabled = $True
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            $this.AddConfig($ConfigObject)
        }

        If($PolicyCount -eq 0)
        {

            # No policy enabling
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem="All"
            $ConfigObject.ConfigData="Enabled False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

            $this.AddConfig($ConfigObject)

        }    

    }

}
