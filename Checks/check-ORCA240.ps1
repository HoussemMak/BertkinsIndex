using module "..\ORCA.psm1"

class ORCA240 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA240()
    {
        $this.Control=240
        $this.Services=[ORCAService]::EOP
        $this.Area=Get-LocalizedString -Key "ORCA240_Area"
        $this.Name=Get-LocalizedString -Key "ORCA240_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA240_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA240_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA240_Importance"
        $this.ChiValue=[ORCACHI]::VeryHigh
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA240_Link_NativeExternal")="https://techcommunity.microsoft.com/t5/exchange-team-blog/native-external-sender-callouts-on-email-in-outlook/ba-p/2250098"
            (Get-LocalizedString -Key "ORCA240_Link_SetExternalInOutlook")="https://learn.microsoft.com/en-us/powershell/module/exchange/set-externalinoutlook?view=exchange-ps"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Check objects
        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object="ExternalInOutlook"
        $ConfigObject.ConfigItem="ExternalInOutlook"
        $ConfigObject.ConfigData=$Config["ExternalInOutlook"].Enabled

        if($Config["ExternalInOutlook"].Enabled -eq $True)
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
        } 
        else 
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
        }

        $this.AddConfig($ConfigObject)

    }

}
