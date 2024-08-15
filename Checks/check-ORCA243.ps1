using module "..\ORCA.psm1"

class ORCA243 : ORCACheck
{
    ORCA243()
    {
        $this.Control=243
        $this.Services=[ORCAService]::EOP
        $this.Area=Get-LocalizedString -Key "ORCA243_Area"
        $this.Name=Get-LocalizedString -Key "ORCA243_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA243_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA243_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA243_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA243_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA243_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA243_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA243_ImprovingDefenseTitle")=Get-LocalizedString -Key "ORCA243_ImprovingDefenseLink"
            (Get-LocalizedString -Key "ORCA243_ConfiguringTitle")=Get-LocalizedString -Key "ORCA243_ConfiguringLink"
        }
    }

    GetResults($Config)
    {
        $ArcTrustedSealers = $($Config["ARCConfig"]).ArcTrustedSealers;
        $HasArcSealer = $ArcTrustedSealers.Length -gt 0

        $DomainsNotAtService = @($($Config["MXReports"] | Where-Object {$_.PointsToService -eq $False}))

        if($DomainsNotAtService.Count -gt 0)
        {
            ForEach($Domain in $($DomainsNotAtService | Select-ExpandProperty Domain | Get-Unique))
            {
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Domain)
                $ConfigObject.ConfigItem="Default ARC Config"
    
                if($HasArcSealer -eq $True)
                {
                    $ConfigObject.ConfigData=$($ArcTrustedSealers)
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                } else {
                    $ConfigObject.ConfigData="No Trusted Sealers"
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                }
    
                $this.AddConfig($ConfigObject)
            }
        } 
    }
}
