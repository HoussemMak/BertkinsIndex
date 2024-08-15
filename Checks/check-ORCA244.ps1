using module "..\ORCA.psm1"

class ORCA244 : ORCACheck
{
    ORCA244()
    {
        $this.Control=244
        $this.Services=[ORCAService]::EOP
        $this.Area=Get-LocalizedString -Key "ORCA244_Area"
        $this.Name=Get-LocalizedString -Key "ORCA244_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA244_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA244_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA244_Importance"
        $this.ExpandResults=$True
        $this.ItemName=Get-LocalizedString -Key "ORCA244_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA244_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.ObjectType=Get-LocalizedString -Key "ORCA244_ObjectType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA244_DmarcHandlingTitle")=Get-LocalizedString -Key "ORCA244_DmarcHandlingLink"
            (Get-LocalizedString -Key "ORCA244_DefenderTitle")=Get-LocalizedString -Key "ORCA244_DefenderLink"
        }
    }

    GetResults($Config)
    {
        ForEach($Policy in $Config["AntiPhishPolicy"]) 
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=$policyname
            $ConfigObject.ConfigData=$($Policy.HonorDmarcPolicy)
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

            If($Policy.HonorDmarcPolicy -eq $true)  
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
