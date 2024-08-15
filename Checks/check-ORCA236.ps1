using module "..\ORCA.psm1"

class ORCA236 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA236()
    {
        $this.Control=236
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA236_Area"
        $this.Name=Get-LocalizedString -Key "ORCA236_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA236_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA236_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA236_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA236_ObjectType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ItemName=Get-LocalizedString -Key "ORCA236_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA236_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA236_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA236_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {

            # Policy is turned on, default false
            $PolicyEnabled = $false

            $PolicyName = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$PolicyName
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA236_ConfigItem"
            $ConfigObject.ConfigData=$Policy.EnableSafeLinksForEmail
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            if($Policy.EnableSafeLinksForEmail -eq $true)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                
            }
            Else
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }
            
            $this.AddConfig($ConfigObject)
        }

    }

}
