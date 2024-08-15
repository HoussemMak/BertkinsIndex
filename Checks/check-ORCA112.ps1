using module "..\ORCA.psm1"

class ORCA112 : ORCACheck
{
    <#
    
        Check if the Anti-spoofing policy action is configured to Move message to the recipients' Junk Email folder as per Standard security settings for Office 365 EOP/MDO
    
    #>

    ORCA112()
    {
        $this.Control="ORCA-112"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA112_Area"
        $this.Name=Get-LocalizedString -Key "ORCA112_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA112_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA112_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA112_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA112_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA112_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA112_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA112_Link_ConfiguringAntiSpoofing")="https://aka.ms/orca-atpp-docs-5"
            (Get-LocalizedString -Key "ORCA112_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
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
            $AuthenticationFailAction = $($Policy.AuthenticationFailAction)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $identity = $($Policy.Identity)
            $enabled = $($Policy.Enabled)
            
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="AuthenticationFailAction"
            $ConfigObject.ConfigData=$AuthenticationFailAction
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If(($enabled -eq $true -and $AuthenticationFailAction -eq "MoveToJmf") -or ($identity -eq "Office365 AntiPhish Default" -and $AuthenticationFailAction -eq "MoveToJmf"))
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            }

            If(($enabled -eq $true -and $AuthenticationFailAction -eq "Quarantine") -or ($identity -eq "Office365 AntiPhish Default" -and $AuthenticationFailAction -eq "Quarantine"))
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)
            }
            
            # Add config to check
            $this.AddConfig($ConfigObject)

        }
        
    
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="AuthenticationFailAction"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            $this.AddConfig($ConfigObject)
        }
        

    }

}
