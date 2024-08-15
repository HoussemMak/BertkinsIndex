using module "..\ORCA.psm1"

class ORCA224 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA224()
    {
        $this.Control=224
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA224_Area"
        $this.Name=Get-LocalizedString -Key "ORCA224_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA224_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA224_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA224_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA224_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA224_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA224_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA224_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA224_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {


        ForEach($Policy in ($Config["AntiPhishPolicy"]))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableSimilarUsersSafetyTips = $($Policy.EnableSimilarUsersSafetyTips)

            #  Determine if tips for user impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="EnableSimilarUsersSafetyTips"
            $ConfigObject.ConfigData=$EnableSimilarUsersSafetyTips
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableSimilarUsersSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")        
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")                       
            }

            $this.AddConfig($ConfigObject)

        }

        # Fail if all policy state is disabled
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableSimilarUsersSafetyTips"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            $this.AddConfig($ConfigObject)
        }             

    }

}
