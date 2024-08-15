using module "..\ORCA.psm1"

class ORCA123 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA123()
    {
        $this.Control=123
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA123_Area"
        $this.Name=Get-LocalizedString -Key "ORCA123_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA123_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA123_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA123_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA123_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA123_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA123_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA123_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in ($Config["AntiPhishPolicy"] | Where-Object {$_.Enabled -eq $True}))
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableUnusualCharactersSafetyTips = $($Policy.EnableUnusualCharactersSafetyTips)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            
            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableUnusualCharactersSafetyTips"
            $ConfigObject.ConfigData=$EnableUnusualCharactersSafetyTips
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableUnusualCharactersSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")       
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                  
            }

            $this.AddConfig($ConfigObject)

        }

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableUnusualCharactersSafetyTips"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }             

    }

}
