using module "..\ORCA.psm1"

class ORCA238 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA238()
    {
        $this.Control=238
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA238_Area"
        $this.Name=Get-LocalizedString -Key "ORCA238_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA238_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA238_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA238_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA238_ObjectType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ItemName=Get-LocalizedString -Key "ORCA238_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA238_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA238_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA238_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
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
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA238_ConfigItem"
            $ConfigObject.ConfigData=$Policy.EnableSafeLinksForOffice
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            if($Policy.EnableSafeLinksForOffice -eq $true)
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
