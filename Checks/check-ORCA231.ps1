using module "..\ORCA.psm1"

class ORCA231 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA231()
    {
        $this.Control=231
        $this.Area=Get-LocalizedString -Key "ORCA231_Area"
        $this.Name=Get-LocalizedString -Key "ORCA231_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA231_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA231_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA231_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA231_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA231_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA231_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA231_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA231_Link_OrderPrecedence")="https://aka.ms/orca-antispam-docs-5"
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

            # Go through each Anti-Spam Policy

            ForEach($Rule in ($Config["HostedContentFilterRule"] | Sort-Object Priority)) 
            {
                if($Rule.State -eq "Enabled")
                {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                    {
                        # Policy applies to this domain

                        $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.HostedContentFilterPolicy)
                            IsPreset=$($Rule.IsPreset)
                            Priority=$($Rule.Priority)
                        }

                    }
                }

            }


            ForEach($Rule in ($Config["EOPProtectionPolicyRule"] | Sort-Object Priority)) 
            {
                if(($Rule.HostedContentFilterPolicy -ne "") -and ($null -ne $Rule.HostedContentFilterPolicy ))
                { 
                   if($Rule.State -eq "Enabled")
                   {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                    {
                            # Policy applies to this domain

                            $Rules += New-Object -TypeName PSObject -Property @{
                                PolicyName=$($Rule.HostedContentFilterPolicy)
                                IsPreset=$($Rule.IsPreset)
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
                
                    $Count++

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$($AcceptedDomain.Name)
                    $ConfigObject.ConfigItem=$r.PolicyName
                    $ConfigObject.ConfigData=$r.Priority

                    If($Count -eq 1)
                    {
                        # First policy based on priority is a pass
                        $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                    }
                    else
                    {
                        # Additional policies based on the priority should be listed as informational
                        $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA231_InfoText_MultiplePolicies"
                        $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                    }    

                    $this.AddConfig($ConfigObject)
                }
            } 
            elseif($Rules.Count -eq 0)
            {
                <#
                    No policy is applying to this domain

                    For anti spam policies this is OK because we fall back to the default
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
