using module "..\ORCA.psm1"

class ORCA239 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA239()
    {
        $this.Control=239
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA239_Area"
        $this.Name=Get-LocalizedString -Key "ORCA239_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA239_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA239_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA239_Importance"
        $this.ItemName=Get-LocalizedString -Key "ORCA239_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA239_DataType"
        $this.ExpandResults=$True
        $this.ChiValue=[ORCACHI]::High
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA239_Link_DefenderPortal")="https://security.microsoft.com/safelinksv2"
            (Get-LocalizedString -Key "ORCA239_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        # Used for passing if no exclusion found
        $ExclusionFound = $false

        foreach($Exclusion in $Config["ATPBuiltInProtectionRule"].ExceptIfSentTo)
        {
            $ExclusionFound = $True

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA239_ConfigItem_Recipient"
            $ConfigObject.ConfigData=$Exclusion
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            $this.AddConfig($ConfigObject)
        }

        foreach($Exclusion in $Config["ATPBuiltInProtectionRule"].ExceptIfSentToMemberOf)
        {
            $ExclusionFound = $True

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA239_ConfigItem_Group"
            $ConfigObject.ConfigData=$Exclusion
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            $this.AddConfig($ConfigObject)
        }


        foreach($Exclusion in $Config["ATPBuiltInProtectionRule"].ExceptIfRecipientDomainIs)
        {
            $ExclusionFound = $True

            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA239_ConfigItem_Domain"
            $ConfigObject.ConfigData=$Exclusion
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
            
            $this.AddConfig($ConfigObject)
        }

        if(!$ExclusionFound)
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA239_ConfigItem_None"
            $ConfigObject.ConfigData=Get-LocalizedString -Key "ORCA239_ConfigData_NoExclusions"
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
            
            $this.AddConfig($ConfigObject)
        }

    }

}
