using module "..\ORCA.psm1"

class ORCA105 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA105()
    {
        $this.Control="ORCA-105"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA105_Area"
        $this.Name=Get-LocalizedString -Key "ORCA105_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA105_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA105_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA105_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA105_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA105_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA105_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA105_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA105_Link_SetupSafeLinks")="https://aka.ms/orca-atpp-docs-10"
            (Get-LocalizedString -Key "ORCA105_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $EnabledPolicyExists = $False

        ForEach($Policy in ($Config["SafeLinksPolicy"] )) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            if(!$IsPolicyDisabled)
            {
                $EnabledPolicyExists = $True
            }

            $DeliverMessageAfterScan =$($Policy.DeliverMessageAfterScan)
            $ScanUrls = $($Policy.ScanUrls)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            <#
            
            DeliverMessageAfterScan
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object= $policyname
                $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA105_ConfigItem_DeliverMessageAfterScan"
                $ConfigObject.ConfigData=$DeliverMessageAfterScan
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                # Determine if DeliverMessageAfterScan is on for this safelinks policy
                If($DeliverMessageAfterScan -eq $true) 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)

                    if(!$IsPolicyDisabled)
                    {
                        $AnyEnabled_DeliverMessageAfterScan = $True
                    }
                }
                Else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
                }

                # Add config to check
                $this.AddConfig($ConfigObject)

            <#
            
            ScanUrls
            
            #>

                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object= $policyname
                $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA105_ConfigItem_ScanUrls"
                $ConfigObject.ConfigData=$ScanUrls
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                If($ScanUrls -eq $true)
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)

                    if(!$IsPolicyDisabled)
                    {
                        $AnyEnabled_ScanUrls = $True
                    }
                }
                Else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
                }

                # Add config to check
                $this.AddConfig($ConfigObject)

        }

        If(!$EnabledPolicyExists)
        {

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=Get-LocalizedString -Key "ORCA105_AllEnabledPolicies"
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA105_ConfigItem_DeliverMessageAfterScan"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            
            # Add config to check
            $this.AddConfig($ConfigObject)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=Get-LocalizedString -Key "ORCA105_AllEnabledPolicies"
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA105_ConfigItem_ScanUrls"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            
            # Add config to check
            $this.AddConfig($ConfigObject)
        }

    }

}
