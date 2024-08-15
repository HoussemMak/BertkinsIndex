using module "..\ORCA.psm1"

class ORCA223 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA223()
    {
        $this.Control=223
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA223_Area"
        $this.Name=Get-LocalizedString -Key "ORCA223_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA223_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA223_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA223_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA223_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA223_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA223_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA223_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA223_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in ($Config["AntiPhishPolicy"] ))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $IsPreset = $Config["PolicyStates"][$Policy.Guid.ToString()].Preset

            $EnableTargetedUserProtection = $($Policy.EnableTargetedUserProtection)
            $TargetedUserProtectionAction = $($Policy.TargetedUserProtectionAction)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Is enabled

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableTargetedUserProtection"
            $ConfigObject.ConfigData=$EnableTargetedUserProtection
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableTargetedUserProtection -eq $False)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            
            $this.AddConfig($ConfigObject)

            # Action

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="TargetedUserProtectionAction"
            $ConfigObject.ConfigData=$TargetedUserProtectionAction
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($TargetedUserProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            }
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")     
            }

            If($TargetedUserProtectionAction -eq "Delete" -or $TargetedUserProtectionAction -eq "Redirect")
            {

                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($Policy.TargetedUserProtectionAction) option may impact the users ability to release emails and may impact user experience."
            }

            
            $this.AddConfig($ConfigObject)

        }

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableTargetedUserProtection"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            # Add config to check
            $this.AddConfig($ConfigObject)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="TargetedUserProtectionAction"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }       

    }

}
