using module "..\ORCA.psm1"

class ORCA158 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA158()
    {
        $this.Control=158
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA158_Area"
        $this.Name=Get-LocalizedString -Key "ORCA158_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA158_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA158_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA158_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA158_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA158_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA158_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA158_Link_DefenderPortal")="https://security.microsoft.com/safeattachmentv2"
            (Get-LocalizedString -Key "ORCA158_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$Config["AtpPolicy"].Name
        $ConfigObject.ConfigItem="EnableATPForSPOTeamsODB"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableATPForSPOTeamsODB
        
        # Determine if MDO is enabled or not
        If($Config["AtpPolicy"].EnableATPForSPOTeamsODB -eq $false) 
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")   
        }
        Else
        {
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")     
        }
        
        $this.AddConfig($ConfigObject)

    }

}
