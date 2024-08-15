using module "..\ORCA.psm1"

class ORCA111 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA111()
    {
        $this.Control="ORCA-111"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA111_Area"
        $this.Name=Get-LocalizedString -Key "ORCA111_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA111_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA111_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA111_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA111_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA111_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA111_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA111_Link_UnverifiedSender")="https://aka.ms/orca-atpp-docs-12"
            (Get-LocalizedString -Key "ORCA111_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach ($Policy in $Config["AntiPhishPolicy"])
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableUnauthenticatedSender = $($Policy.EnableUnauthenticatedSender)

            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $identity = $($Policy.Identity)
            $enabled = $($Policy.Enabled)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableUnauthenticatedSender"
            $ConfigObject.ConfigData=$EnableUnauthenticatedSender
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If(($enabled -eq $true -and $EnableUnauthenticatedSender -eq $true) -or ($identity -eq "Office365 AntiPhish Default" -and $EnableUnauthenticatedSender -eq $true))
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

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableUnauthenticatedSender"
            $ConfigObject.ConfigData="False"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            $this.AddConfig($ConfigObject)
        }
    }

}
