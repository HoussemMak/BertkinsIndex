using module "..\ORCA.psm1"

class ORCA113 : ORCACheck
{
    <#
    
        Check if AllowClickThrough is disabled in the organisation wide SafeLinks policy and if AllowClickThrough is True in SafeLink policies
    
    #>

    ORCA113()
    {
        $this.Control="ORCA-113"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA113_Area"
        $this.Name=Get-LocalizedString -Key "ORCA113_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA113_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA113_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA113_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA113_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA113_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA113_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA113_Link_SafeLinksPolicies")="https://aka.ms/orca-atpp-docs-11"
            (Get-LocalizedString -Key "ORCA113_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-8"
        }
    
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $PolicyCount = 0
       
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {    
            # Built-in policy is ignored for this check

            if(!$Config["PolicyStates"][$Policy.Guid.ToString()].IsBuiltIn)
            {
                $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $AllowClickThrough = $($Policy.AllowClickThrough)

                # If not disabled, increment policy count
                if(!$IsPolicyDisabled)
                {
                    $PolicyCount++
                }

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
                $ConfigObject.ConfigItem="AllowClickThrough"
                $ConfigObject.ConfigData=$AllowClickThrough
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                # Determine if AllowClickThrough is True in safelinks policies
                If($Policy.AllowClickThrough -eq $false)
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                }
                Else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")                 
                }

                # Add config to check
                $this.AddConfig($ConfigObject)
            }
        }

        if($PolicyCount -eq 0)
        {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object="All non-built in policies"
                $ConfigObject.ConfigItem="AllowClickThrough"
                $ConfigObject.ConfigData="Disabled"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                $this.AddConfig($ConfigObject)
        }

    }

}
