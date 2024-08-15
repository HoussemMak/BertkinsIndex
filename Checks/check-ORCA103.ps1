using module "..\ORCA.psm1"

class ORCA103 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA103()
    {
        $this.Control="ORCA-103"
        $this.Area=Get-LocalizedString -Key "ORCA103_Area"
        $this.Name=Get-LocalizedString -Key "ORCA103_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA103_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA103_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA103_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA103_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA103_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA103_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
                (Get-LocalizedString -Key "ORCA103_Link_DefenderPortal")="https://security.microsoft.com/antispam"
                (Get-LocalizedString -Key "ORCA103_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
            }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in $Config["HostedOutboundSpamFilterPolicy"])
        {

            <#
            
                RecipientLimitExternalPerHour
            
            #>

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $RecipientLimitExternalPerHour = $($Policy.RecipientLimitExternalPerHour)
            $RecipientLimitInternalPerHour = $($Policy.RecipientLimitInternalPerHour)
            $RecipientLimitPerDay = $($Policy.RecipientLimitPerDay)
            $ActionWhenThresholdReached = $($Policy.ActionWhenThresholdReached)

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitExternalPerHour"
            $ConfigObject.ConfigData=$RecipientLimitExternalPerHour
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Recipient per hour limit for standard is 500
            If($RecipientLimitExternalPerHour -eq 500)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)               
            }

            # Recipient per hour limit for strict is 400
            If($RecipientLimitExternalPerHour -eq 400)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitInternalPerHour
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitInternalPerHour"
            $ConfigObject.ConfigData=$($RecipientLimitInternalPerHour)
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($RecipientLimitInternalPerHour -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)               
            }

            If($RecipientLimitInternalPerHour -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            <#
            
                RecipientLimitPerDay
            
            #>
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="RecipientLimitPerDay"
            $ConfigObject.ConfigData=$($RecipientLimitPerDay)
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($RecipientLimitPerDay -eq 1000)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)               
            }

            If($RecipientLimitPerDay -eq 800)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)              
            }

            # Add config to check
            $this.AddConfig($ConfigObject)

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="ActionWhenThresholdReached"
            $ConfigObject.ConfigData=$($ActionWhenThresholdReached)
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset

            If($ActionWhenThresholdReached -like "BlockUser")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)               
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }
    }

}
