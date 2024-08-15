using module "..\ORCA.psm1"

class ORCA100 : ORCACheck
{
    ORCA100()
    {
        $this.Control = "ORCA-100"
        $this.Area = Get-LocalizedString -Key "ORCA100_Area"
        $this.Name = Get-LocalizedString -Key "ORCA100_Name"
        $this.PassText = Get-LocalizedString -Key "ORCA100_PassText"
        $this.FailRecommendation = Get-LocalizedString -Key "ORCA100_FailRecommendation"
        $this.Importance = Get-LocalizedString -Key "ORCA100_Importance"
        $this.ExpandResults = $True
        $this.ItemName = Get-LocalizedString -Key "ORCA100_ItemName"
        $this.DataType = Get-LocalizedString -Key "ORCA100_DataType"
        $this.Links = @{
            (Get-LocalizedString -Key "ORCA100_Link_BulkComplaintLevelValues") = "https://aka.ms/orca-antispam-docs-1"
            (Get-LocalizedString -Key "ORCA100_Link_RecommendedSettings") = "https://aka.ms/orca-atpp-docs-6"
            (Get-LocalizedString -Key "ORCA100_Link_MicrosoftDefenderPortal") = "https://security.microsoft.com/antispam"
        }
    }

    GetResults($Config)
    {
        ForEach($Policy in $Config["HostedContentFilterPolicy"])
        {
            $BulkThreshold = $($Policy.BulkThreshold)

            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem = $Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigData = $BulkThreshold
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly = $Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid = $Policy.Guid.ToString()

            # Standard check - between 4 and 6
            If($BulkThreshold -ge 4 -and $BulkThreshold -le 6)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard, [ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard, [ORCAResult]::Fail)
            }

            # Strict check - is 4
            If($BulkThreshold -eq 4)
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict, [ORCAResult]::Pass)
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict, [ORCAResult]::Fail)
            }

            # Add config to check
            $this.AddConfig($ConfigObject)
        }
    }
}
