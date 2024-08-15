using module "..\ORCA.psm1"

class ORCA232 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA232()
    {
        $this.Control=232
        $this.Area=Get-LocalizedString -Key "ORCA232_Area"
        $this.Name=Get-LocalizedString -Key "ORCA232_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA232_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA232_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA232_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA232_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA232_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA232_DataType"
        $this.ChiValue=[ORCACHI]::Medium
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA232_Link_DefenderPortal")="https://security.microsoft.com/antimalwarev2"
            (Get-LocalizedString -Key "ORCA232_Link_OrderPrecedence")="https://aka.ms/orca-atpp-docs-4"
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

            # Go through each Safe Links Policy

            ForEach($Rule in ($Config["MalwareFilterRule"] | Sort-Object Priority)) 
            {
                if( $Rule.State -eq "Enabled")
                {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                         {
                        # Policy applies to this domain

                        $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.MalwareFilterPolicy)
                            Priority=$($Rule.Priority)
                        }

                    }
                }

            }
            ForEach($Rule in ($Config["EOPProtectionPolicyRule"] | Sort-Object Priority)) 
            {
                if(($Rule.MalwareFilterPolicy -ne "") -and ($null -ne $Rule.MalwareFilterPolicy ))
                { 
                   if($Rule.State -eq "Enabled")
                   {
                    if($Rule.RecipientDomainIs -contains $AcceptedDomain.Name -and ($Rule.ExceptIfRecipientDomainIs -notcontains $AcceptedDomain.Name) -and ($null -eq $Rule.ExceptIfSentToMemberOf ) -and ($null -eq $Rule.ExceptIfSentTo) )
                    {
                            # Policy applies to this domain

                            $Rules += New-Object -TypeName PSObject -Property @{
                            PolicyName=$($Rule.MalwareFilterPolicy)
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
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA232_InfoText_BuiltIn"
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
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA232_InfoText_BuiltIn"
                            $ConfigObject.SetResult([ORCAConfigLevel]::Informational,"Fail")
                        }
                        else
                        {
                        # Additional policies based on the priority should be listed as informational
                            $ConfigObject.InfoText = Get-LocalizedString -Key "ORCA232_InfoText_MultiplePolicies"
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

                    For anti malware policies this is OK because we fall back to the default
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
