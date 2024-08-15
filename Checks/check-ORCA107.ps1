using module "..\ORCA.psm1"

class ORCA107 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA107()
    {
        $this.Control="ORCA-107"
        $this.Area=Get-LocalizedString -Key "ORCA107_Area"
        $this.Name=Get-LocalizedString -Key "ORCA107_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA107_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA107_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA107_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Quarantine Policy"
        $this.ItemName=Get-LocalizedString -Key "ORCA107_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA107_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA107_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA107_Link_EndUserNotifications")="https://aka.ms/orca-antispam-docs-2"
            (Get-LocalizedString -Key "ORCA107_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        $GlobalPolicy = $Config["QuarantinePolicyGlobal"]

        ForEach($QuarantinePolicy in $Config["QuarantinePolicy"])
        {

            $AppliesSpam = $False
            $AppliesPhish = $False

            ForEach($Policy in $Config["HostedContentFilterPolicy"])
            {
                if($Config["PolicyStates"][$Policy.Guid.ToString()].Applies -eq $True)
                {
                    # Check Spam action
                    if($Policy.SpamAction -eq "Quarantine" -and $Policy.SpamQuarantineTag -eq $QuarantinePolicy.Name)
                    {
                        $AppliesSpam = $True
                    }

                    # Check HC Spam Action
                    if($Policy.HighConfidenceSpamAction -eq "Quarantine" -and $Policy.HighConfidenceSpamQuarantineTag -eq $QuarantinePolicy.Name)
                    {
                        $AppliesSpam = $True
                    }

                    # Check Bulk Action
                    if($Policy.BulkSpamAction -eq "Quarantine" -and $Policy.BulkQuarantineTag -eq $QuarantinePolicy.Name)
                    {
                        $AppliesSpam = $True
                    }

                    # Check Phish Action
                    if($Policy.PhishSpamAction -eq "Quarantine" -and $Policy.PhishQuarantineTag -eq $QuarantinePolicy.Name)
                    {
                        $AppliesPhish = $True
                    }

                    # Check HC Phish Action
                    if($Policy.HighConfidencePhishAction -eq "Quarantine" -and $Policy.HighConfidencePhishQuarantineTag -eq $QuarantinePolicy.Name)
                    {
                        $AppliesPhish = $True
                    }
                }
            }
            
            $ConfigObject = [ORCACheckConfig]::new()
            $ConfigObject.Object=$QuarantinePolicy.Name
            $ConfigObject.ConfigReadonly=($QuarantinePolicy.Name -eq "DefaultFullAccessWithNotificationPolicy" -or $QuarantinePolicy.Name -eq "DefaultFullAccessPolicy" -or $QuarantinePolicy.Name -eq "AdminOnlyAccessPolicy")
            $ConfigObject.ConfigItem="ESNEnabled"
            $ConfigObject.ConfigData = $QuarantinePolicy.ESNEnabled

            if($AppliesSpam)
            {
                if($QuarantinePolicy.ESNEnabled -eq $True)
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)
                } 
                else 
                {
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)
                }
                
                $this.AddConfig($ConfigObject)
            } 
            else 
            {
                # Quarantine policy does not apply to any spam policy
                if($QuarantinePolicy.ESNEnabled -eq $False)
                {
                    $ConfigObject.ConfigDisabled = $True
                    $ConfigObject.SetResult([ORCAConfigLevel]::All,[ORCAResult]::Informational)
                    $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA107_InfoText"
                
                    $this.AddConfig($ConfigObject)
                }
            }

        }        
    }

}
