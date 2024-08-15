using module "..\ORCA.psm1"

class ORCA229 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA229()
    {
        $this.Control=229
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA229_Area"
        $this.Name=Get-LocalizedString -Key "ORCA229_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA229_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA229_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA229_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA229_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA229_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA229_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA229_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA229_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
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
            $ExcludedDomains = $($Policy.ExcludedDomains)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            
            If(($ExcludedDomains).Count -gt 0)
            {
                ForEach($Domain in $ExcludedDomains) 
                {
                    # Check objects
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="ExcludedDomains"
                    $ConfigObject.ConfigData=$($Domain)
                    $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                    $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                    $this.AddConfig($ConfigObject)  
                }
            }
            else 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="ExcludedDomains"
                $ConfigObject.ConfigData=Get-LocalizedString -Key "ORCA229_NoDomainDetected"
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $this.AddConfig($ConfigObject)  
            }
        }      

    }

}
