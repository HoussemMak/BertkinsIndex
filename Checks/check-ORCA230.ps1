using module "..\ORCA.psm1"

class ORCA230 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA230()
    {
        $this.Control=230
        $this.Services=[ORCAService]::MDO
        $this.Area=Get-LocalizedString -Key "ORCA230_Area"
        $this.Name=Get-LocalizedString -Key "ORCA230_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA230_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA230_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA230_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA230_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA230_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA230_DataType"
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA230_Link_DefenderPortal")="https://security.microsoft.com/antiphishing"
            (Get-LocalizedString -Key "ORCA230_Link_OrderPrecedence")="https://aka.ms/orca-atpp-docs-4"
            (Get-LocalizedString -Key "ORCA230_Link_SettingUp")="https://aka.ms/orca-atpp-docs-2"
            (Get-LocalizedString -Key "ORCA230_Link_Settings")="https://aka.ms/orca-atpp-docs-7"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        ForEach($AcceptedDomain in $Config["AcceptedDomains"]) 
        {

            # Set up the config object

            $Rules = @()

            # Go through each Anti-Phishing Policy

            ForEach($Rule in ($Config["AntiPhishRules"] | Sort-Object Priority)) 
            {
                if($Rule.State -eq "Enabled")
                {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                    {
                        # Policy applies to this domain

                        $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.AntiPhishPolicy)
                            Priority=$($Rule.Priority)
                        }

                    }
                }

            }
            ForEach($Rule in ($Config["EOPProtectionPolicyRule"] | Sort-Object Priority)) 
            {
                if(($Rule.AntiPhishPolicy -ne "") -and ($null -ne $Rule.AntiPhishPolicy ))
                { 
                   if($Rule.State -eq "Enabled")
                   {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                    {
                            # Policy applies to this domain

                            $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.AntiPhishPolicy)
                            Priority=$($Rule.Priority)
                            }

                        }   
                    }
                }
            }
            If($Rules.Count -gt 0)
            {
                $Count = 0
                $CountOfPolicies = ($Rules).Count
                ForEach($r in ($Rules | Sort-Object Priority))
                {

                    $IsBuiltIn = $false
                    $policyname = $($r.PolicyName)
                    $priority =$($r.Priority)
                    if($policyname -match "Built-In" -and $CountOfPolicies -gt 1)
                    {
                        $IsBuiltIn =$True
                        $policyname = "$policyname" +" [Built-In]"
                    }
                    elseif(($policyname -eq "Default" -or $policyname -eq "Office365 AntiPhish Default") -and $CountOfPolicies -gt 1)
                    {
                        $IsBuiltIn =$True
                        $policyname = "$policyname" +" [Default]"
                    }

                    $Count++

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($AcceptedDomain.Name)
                    $ConfigObject.ConfigItem=$policyname
                    $ConfigObject.ConfigData=$priority

                    If($Count -eq 1)
                    {
                        # First policy based on priority is a pass
                        if($IsBuiltIn)
                        {
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA230_InfoText_BuiltIn"
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                        else
                        {
                            $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                        }
                    }
                    else
                    {
                        if($IsBuiltIn)
                        {
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA230_InfoText_BuiltIn"
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                        else
                        {
                        # Additional policies based on the priority should be listed as informational
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA230_InfoText_MultiplePolicies"
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                    }    

                    $this.AddConfig($ConfigObject)
                }
            } 
            elseif($Rules.Count -eq 0)
            {
                <#
                    No policy is applying to this domain

                    For anti-phishing this is OK because we fall back to the default
                #>
                
                $ConfigObject = [ORCACheckConfig]::new()

                $ConfigObject.Object=$($AcceptedDomain.Name)
                $ConfigObject.ConfigItem="Default"
                $ConfigObject.ConfigData="Default"
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")

                $this.AddConfig($ConfigObject)
            }

        }

    }

}
