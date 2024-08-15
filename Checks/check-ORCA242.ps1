using module "..\ORCA.psm1"

class ORCA242 : ORCACheck
{
    <#

        Check for first contact safety tip

    #>

    ORCA242()
    {
        $this.Control=242
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA242_Area"
        $this.Name=Get-LocalizedString -Key "ORCA242_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA242_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA242_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA242_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType="Protection Alert"
        $this.ItemName="Setting"
        $this.DataType="Current Value"
        $this.ChiValue=[ORCACHI]::Critical
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA242_Link_AutoIR")="https://learn.microsoft.com/en-us/microsoft-365/security/defender/m365d-autoir"
        }
    }

    <#

        RESULTS

    #>

    GetResults($Config)
    {

        $ImportantAlerts = @(
            "A potentially malicious URL click was detected",
            "Teams message reported by user as security risk",
            "Email messages containing phish URLs removed after delivery",
            "Suspicious Email Forwarding Activity",
            "Malware not zapped because ZAP is disabled",
            "Phish delivered due to an ETR override",
            "Email messages containing malicious file removed after delivery",
            "Email reported by user as malware or phish",
            "Email messages containing malicious URL removed after delivery",
            "Email messages containing malware removed after delivery",
            "A user clicked through to a potentially malicious URL",
            "Email messages from a campaign removed after delivery",
            "Email messages removed after delivery",
            "Suspicious email sending patterns detected"
        )

        if($Config.ContainsKey('ProtectionAlert'))
        {
            ForEach ($ImportantAlert in $ImportantAlerts)
            {
                $FoundAlert = $Config["ProtectionAlert"] | Where-Object {$_.Name -eq $ImportantAlert}

                if($null -ne $FoundAlert)
                {
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object=$ImportantAlert
                    $ConfigObject.ConfigItem="Disabled"
                    $ConfigObject.ConfigData=$FoundAlert.Disabled

                    if($FoundAlert.Disabled)
                    {
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    } 
                    else 
                    {
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                    }

                    $this.AddConfig($ConfigObject)
                }
            }

        }

    }

}
