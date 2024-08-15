using module "..\ORCA.psm1"

class ORCA119 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA119()
    {
        $this.Control="ORCA-119"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA119_Area"
        $this.Name=Get-LocalizedString -Key "ORCA119_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA119_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA119_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA119_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA119_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA119_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA119_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA119_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-7"
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
            $EnableSimilarDomainsSafetyTips = $($Policy.EnableSimilarDomainsSafetyTips)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            #  Determine if tips for domain impersonation is on

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="EnableSimilarDomainsSafetyTips"
            $ConfigObject.ConfigData=$EnableSimilarDomainsSafetyTips
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($EnableSimilarDomainsSafetyTips -eq $false)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)          
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)                        
            }

            $this.AddConfig($ConfigObject)

        }
        
        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="EnableSimilarDomainsSafetyTips"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            $this.AddConfig($ConfigObject)
        }  

    }

}
