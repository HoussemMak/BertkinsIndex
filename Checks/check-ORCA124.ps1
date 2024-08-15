using module "..\ORCA.psm1"

class ORCA124 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA124()
    {
        $this.Control=124
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA124_Area"
        $this.Name=Get-LocalizedString -Key "ORCA124_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA124_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA124_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA124_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Safe Attachments Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA124_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA124_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA124_Link_DefenderPortal")="https://security.microsoft.com/safeattachmentv2"
            (Get-LocalizedString -Key "ORCA124_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        <#
        
        This check does not need a default response where no policies exist,
        because the 'Built-In Protection Policy' has this turned on.
        
        #>
       
        ForEach($Policy in $Config["SafeAttachmentsPolicy"]) 
        {
            # Check objects
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$Config["PolicyStates"][$Policy.Guid.ToString()].Name
            $ConfigObject.ConfigItem="Action"
            $ConfigObject.ConfigData=$($Policy.Action)
            $ConfigObject.ConfigReadonly=$Policy.IsPreset
            $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
            
            # Determine if MDO Safe attachments action is set to block
            If($($Policy.Action) -ne "Block") 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
            } 
            Else 
            {
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
            }

            If($($Policy.Action) -eq "Replace" -or $($Policy.Action) -eq "DynamicDelivery")
            {
                $ConfigObject.InfoText = "Attachments with detected malware will be blocked, the body of the email message delivered to the recipient."
                $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
            }

            $this.AddConfig($ConfigObject)
        }

    }

}
