using module "..\ORCA.psm1"

class ORCA228 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA228()
    {
        $this.Control=228
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA228_Area"
        $this.Name=Get-LocalizedString -Key "ORCA228_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA228_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA228_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA228_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA228_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA228_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA228_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA228_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA228_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
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

            $ExcludedSenders = $($Policy.ExcludedSenders)

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="ExcludedSenders"
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If(($ExcludedSenders).count -eq 0)
            {
                $ConfigObject.ConfigData="No Sender Detected"    
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")       
            }
            Else 
            {
                $ConfigObject.ConfigData=$ExcludedSenders
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")                       
            }

            $this.AddConfig($ConfigObject)

        }    

    }

}
