using module "..\ORCA.psm1"

class ORCA116 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA116()
    {
        $this.Control="ORCA-116"
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA116_Area"
        $this.Name=Get-LocalizedString -Key "ORCA116_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA116_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA116_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA116_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Antiphishing Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA116_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA116_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            (Get-LocalizedString -Key "ORCA116_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA116_Link_SetupPolicies")="https://aka.ms/orca-atpp-docs-9"
            (Get-LocalizedString -Key "ORCA116_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-7"
        }   
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        <#
        
        This check does not need a default catch all as the default anti-phishing policy cannot be disabled
        
        #>
       
        ForEach($Policy in ($Config["AntiPhishPolicy"] ))
        {

            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $MailboxIntelligenceProtectionAction = $($Policy.MailboxIntelligenceProtectionAction)

            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Determine if Mailbox Intelligence Protection action is configured

            $ConfigObject = [ORCACheckConfig]::new()

            $ConfigObject.Object=$policyname
            $ConfigObject.ConfigItem="MailboxIntelligenceProtectionAction"
            $ConfigObject.ConfigData=$MailboxIntelligenceProtectionAction
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            
            # For standard, this should be MoveToJmf
            If($MailboxIntelligenceProtectionAction -ne "MoveToJmf")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)       
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)               
            }

            # For strict, this should be Quarantine
            If($MailboxIntelligenceProtectionAction -ne "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Fail)        
            }
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Strict,[ORCAResult]::Pass)                         
            }

            # For either Delete or Quarantine we should raise an informational
            If($MailboxIntelligenceProtectionAction -eq "Delete" -or $MailboxIntelligenceProtectionAction -eq "Quarantine")
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA116_InfoText" -f $MailboxIntelligenceProtectionAction
            }

            $this.AddConfig($ConfigObject)

        }

        If($Config["AnyPolicyState"][[PolicyType]::Antiphish] -eq $False)
        {
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object="No Enabled Policies"
            $ConfigObject.ConfigItem="MailboxIntelligenceProtectionAction"
            $ConfigObject.ConfigData=""
            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            $this.AddConfig($ConfigObject)
        }


    }

}
