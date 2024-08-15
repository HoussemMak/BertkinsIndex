using module "..\ORCA.psm1"

class ORCA156 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA156()
    {
        $this.Control=156
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA156_Area"
        $this.Name=Get-LocalizedString -Key "ORCA156_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA156_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA156_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA156_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA156_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA156_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA156_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA156_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA156_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {   
       
        ForEach($Policy in $Config["SafeLinksPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $TrackUserClicks = $($Policy.TrackClicks)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="TrackClicks"
            $ConfigObject.ConfigData=$TrackUserClicks
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            # Determine if MDO link tracking is on for this safelinks policy
            If($TrackUserClicks -eq $True)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            } 
            else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
            
        }        

    }

}
