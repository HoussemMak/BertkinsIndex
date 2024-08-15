using module "..\ORCA.psm1"

class ORCA222 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA222()
    {
        $this.Control=222
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA222_Area"
        $this.Name=Get-LocalizedString -Key "ORCA222_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA222_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA222_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA222_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA222_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA222_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA222_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA222_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA222_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        <#
        
        This check does not need a default fail if no policies exist
        
        #>

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $EnableTargetedDomainsProtection = $($Policy.EnableTargetedDomainsProtection)
            $EnableOrganizationDomainsProtection = $($Policy.EnableOrganizationDomainsProtection)
            $TargetedDomainProtectionAction = $($Policy.TargetedDomainProtectionAction)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            <#
            
            EnableTargetedDomainsProtection / EnableOrgainizationDomainsProtection
            
            #>

            If($EnableTargetedDomainsProtection -eq $False -and $EnableOrganizationDomainsProtection -eq $False)
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$EnableTargetedDomainsProtection
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly = $Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                $this.AddConfig($ConfigObject)
                
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$EnableOrganizationDomainsProtection
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly = $Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")

                $this.AddConfig($ConfigObject)       
            }
            
            If($EnableTargetedDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableTargetedDomainsProtection"
                $ConfigObject.ConfigData=$EnableTargetedDomainsProtection
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly = $Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)

            }
    
            If($EnableOrganizationDomainsProtection -eq $True)
            {

                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="EnableOrganizationDomainsProtection"
                $ConfigObject.ConfigData=$EnableOrganizationDomainsProtection
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly = $Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)
         
            }

            
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="TargetedDomainProtectionAction"
            $ConfigObject.ConfigData=$TargetedDomainProtectionAction
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($TargetedDomainProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")          
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail") 
            }

            If($TargetedDomainProtectionAction -eq "Delete" -or $TargetedDomainProtectionAction -eq "Redirect")
            {
                # For either Delete or Quarantine we should raise an informational
                $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                $ConfigObject.InfoText = "The $($TargetedDomainProtectionAction) option may impact the users ability to release emails and may impact user experience."
            }

            $this.AddConfig($ConfigObject)
    
        } 

    }

}
