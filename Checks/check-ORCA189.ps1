using module "..\ORCA.psm1"

class ORCA189 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA189()
    {
        $this.Control=189
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA189_Area"
        $this.Name=Get-LocalizedString -Key "ORCA189_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA189_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA189_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA189_Importance"
        $this.ExpandResults=$True
        $this.ObjectType=Get-LocalizedString -Key "ORCA189_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA189_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA189_DataType"
        $this.CheckType = [CheckType]::ObjectPropertyValue
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA189_Link_ExchangeAdminCenter")="https://outlook.office365.com/ecp/"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $BypassRules = @($Config["TransportRules"] | Where-Object {$_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing"})
        
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
