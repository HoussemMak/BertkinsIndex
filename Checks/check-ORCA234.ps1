using module "..\ORCA.psm1"

class ORCA234 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA234()
    {
        $this.Control=234
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA234_Area"
        $this.Name=Get-LocalizedString -Key "ORCA234_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA234_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA234_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA234_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA234_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA234_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA234_DataType"
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA234_Link_SafeAttachments")="https://security.microsoft.com/safeattachmentv2"
            (Get-LocalizedString -Key "ORCA234_Link_SafeDocuments")="https://aka.ms/orca-atpp-docs-1"
            (Get-LocalizedString -Key "ORCA234_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $ConfigObject = [ORCACheckConfig]::new()
        $ConfigObject.Object=$Config["AtpPolicy"].Name
        $ConfigObject.ConfigItem="AllowSafeDocsOpen"
        $ConfigObject.ConfigData=$Config["AtpPolicy"].AllowSafeDocsOpen
        # Determine if click through for SafeDocs in MDO is enabled or not
        If($Config["AtpPolicy"].AllowSafeDocsOpen -eq $true) 
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
