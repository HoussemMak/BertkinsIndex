using module "..\ORCA.psm1"

class ORCA225 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA225()
    {
        $this.Control=225
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA225_Area"
        $this.Name=Get-LocalizedString -Key "ORCA225_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA225_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA225_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA225_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA225_ObjectType"
        $this.ChiValue=[ORCACHI]::High
        $this.ItemName=Get-LocalizedString -Key "ORCA225_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA225_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA225_Link_DefenderPortal")="https://security.microsoft.com/safeattachmentv2"
            (Get-LocalizedString -Key "ORCA225_Link_SafeDocs")="https://aka.ms/orca-atpp-docs-1"
            (Get-LocalizedString -Key "ORCA225_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$Config["AtpPolicy"].Name
        $ConfigObject.ConfigItem="EnableSafeDocs"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].EnableSafeDocs

        # Determine if SafeDocs in MDO is enabled or not
        If($Config["AtpPolicy"].EnableSafeDocs -eq $false) 
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
