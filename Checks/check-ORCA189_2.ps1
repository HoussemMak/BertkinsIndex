using module "..\ORCA.psm1"

class ORCA189_2 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA189_2()
    {
        $this.Control="189-2"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA189_2_Area"
        $this.Name=Get-LocalizedString -Key "ORCA189_2_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA189_2_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA189_2_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA189_2_Importance"
        $this.ExpandResults=$True
        $this.ObjectType=Get-LocalizedString -Key "ORCA189_2_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA189_2_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA189_2_DataType"
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA189_2_Link_ExchangeAdminCenter")="https://outlook.office365.com/ecp/"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $BypassRules = @($Config["TransportRules"] | Where-Object {$_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeLinksProcessing"})
        
        If($BypassRules.Count -gt 0) 
        {
            # Rules exist to bypass
            ForEach($Rule in $BypassRules) 
            {
                # Check objects
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$($Rule.Name)
                $ConfigObject.ConfigItem=$($Rule.SetHeaderName)
                $ConfigObject.ConfigData=$($Rule.SetHeaderValue)
                $ConfigObject.ConfigDisabled=$($Rule.State -eq "Disabled")
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                $this.AddConfig($ConfigObject)  

            }
        }   

    }

}
