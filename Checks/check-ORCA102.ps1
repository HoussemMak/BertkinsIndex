using module "..\ORCA.psm1"

class ORCA102 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA102()
    {
        $this.Control="ORCA-102"
        $this.Area=Get-LocalizedString -Key "ORCA102_Area"
        $this.Name=Get-LocalizedString -Key "ORCA102_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA102_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA102_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA102_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA102_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA102_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA102_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links=@{
            (Get-LocalizedString -Key "ORCA102_Link_DefenderPortal")="https://security.microsoft.com/antispam"
            (Get-LocalizedString -Key "ORCA102_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {
        #$CountOfPolicies = ($Config["HostedContentFilterPolicy"]).Count
        $CountOfPolicies = ($global:HostedContentPolicyStatus| Where-Object {$_.IsEnabled -eq $True}).Count
        ForEach($Policy in $Config["HostedContentFilterPolicy"]) {

            $IsPolicyDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
            $ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies

            $IncreaseScoreWithImageLinks = $($Policy.IncreaseScoreWithImageLinks) 
            $IncreaseScoreWithNumericIps = $($Policy.IncreaseScoreWithNumericIps) 
            $IncreaseScoreWithRedirectToOtherPort = $($Policy.IncreaseScoreWithRedirectToOtherPort) 
            $IncreaseScoreWithBizOrInfoUrls = $($Policy.IncreaseScoreWithBizOrInfoUrls) 
            $MarkAsSpamEmptyMessages = $($Policy.MarkAsSpamEmptyMessages) 
            $MarkAsSpamJavaScriptInHtml = $($Policy.MarkAsSpamJavaScriptInHtml) 
            $MarkAsSpamFramesInHtml = $($Policy.MarkAsSpamFramesInHtml) 
            $MarkAsSpamObjectTagsInHtml = $($Policy.MarkAsSpamObjectTagsInHtml) 
            $MarkAsSpamEmbedTagsInHtml = $($Policy.MarkAsSpamEmbedTagsInHtml) 
            $MarkAsSpamFormTagsInHtml = $($Policy.MarkAsSpamFormTagsInHtml) 
            $MarkAsSpamWebBugsInHtml = $($Policy.MarkAsSpamWebBugsInHtml) 
            $MarkAsSpamSensitiveWordList = $($Policy.MarkAsSpamSensitiveWordList) 
            $MarkAsSpamFromAddressAuthFail = $($Policy.MarkAsSpamFromAddressAuthFail) 
            $MarkAsSpamNdrBackscatter = $($Policy.MarkAsSpamNdrBackscatter) 
            $MarkAsSpamSpfRecordHardFail = $($Policy.MarkAsSpamSpfRecordHardFail) 
           
            $IsBuiltIn = $false
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Determine if ASF options are off or not
            If($IncreaseScoreWithImageLinks -eq "On" -or $IncreaseScoreWithNumericIps -eq "On" -or $IncreaseScoreWithRedirectToOtherPort -eq "On" -or $IncreaseScoreWithBizOrInfoUrls -eq "On" -or $MarkAsSpamEmptyMessages -eq "On" -or $MarkAsSpamJavaScriptInHtml -eq "On" -or $MarkAsSpamFramesInHtml -eq "On" -or $MarkAsSpamObjectTagsInHtml -eq "On" -or $MarkAsSpamEmbedTagsInHtml -eq "On" -or $MarkAsSpamFormTagsInHtml -eq "On" -or $MarkAsSpamWebBugsInHtml -eq "On" -or $MarkAsSpamSensitiveWordList -eq "On" -or $MarkAsSpamFromAddressAuthFail -eq "On" -or $MarkAsSpamNdrBackscatter -eq "On" -or $MarkAsSpamSpfRecordHardFail -eq "On") {
                If($IncreaseScoreWithImageLinks -eq "On") {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithImageLinks"
                    $ConfigObject.ConfigData=$IncreaseScoreWithImageLinks
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($IncreaseScoreWithNumericIps -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithNumericIps"
                    $ConfigObject.ConfigData=$IncreaseScoreWithNumericIps
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($IncreaseScoreWithRedirectToOtherPort -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()

                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithRedirectToOtherPort"
                    $ConfigObject.ConfigData=$IncreaseScoreWithRedirectToOtherPort
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($IncreaseScoreWithBizOrInfoUrls -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="IncreaseScoreWithBizOrInfoUrls"
                    $ConfigObject.ConfigData=$IncreaseScoreWithBizOrInfoUrls
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamEmptyMessages -eq "On") 
                {

                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamEmptyMessages"
                    $ConfigObject.ConfigData=$MarkAsSpamEmptyMessages
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamJavaScriptInHtml -eq "On") 
                {
                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamJavaScriptInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamJavaScriptInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamFramesInHtml -eq "On") {
                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFramesInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamFramesInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamObjectTagsInHtml -eq "On") 
                {
                                                            
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamObjectTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamObjectTagsInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamEmbedTagsInHtml -eq "On") 
                {
                                                                                
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamEmbedTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamEmbedTagsInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamFormTagsInHtml -eq "On") 
                {
                                                                                                    
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFormTagsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamFormTagsInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamWebBugsInHtml -eq "On") 
                {
                                                                                                                        
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamWebBugsInHtml"
                    $ConfigObject.ConfigData=$MarkAsSpamWebBugsInHtml
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamSensitiveWordList -eq "On") 
                {
                                                                                                                                      
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamSensitiveWordList"
                    $ConfigObject.ConfigData=$MarkAsSpamSensitiveWordList
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamFromAddressAuthFail -eq "On") 
                {
                                                                                                                                                          
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamFromAddressAuthFail"
                    $ConfigObject.ConfigData=$MarkAsSpamFromAddressAuthFail
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamNdrBackscatter -eq "On") 
                {
                                                                                                                                                                              
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamNdrBackscatter"
                    $ConfigObject.ConfigData=$MarkAsSpamNdrBackscatter
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
                If ($MarkAsSpamSpfRecordHardFail -eq "On") 
                {
                                                                                                                                                                             
                    $ConfigObject = [ORCACheckConfig]::new()
                    
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="MarkAsSpamSpfRecordHardFail"
                    $ConfigObject.ConfigData=$MarkAsSpamSpfRecordHardFail
                    $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                    $ConfigObject.ConfigWontApply=$ConfigWontApply
                    $ConfigObject.ConfigReadonly=$Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Fail)

                    $this.AddConfig($ConfigObject)

                }
    
            }
            else 
            {
                                                                                                                                                                        
                $ConfigObject = [ORCACheckConfig]::new()
                    
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem=Get-LocalizedString -Key "ORCA102_ConfigItem"
                $ConfigObject.ConfigData=Get-LocalizedString -Key "ORCA102_ConfigData"
                $ConfigObject.ConfigDisabled=$IsPolicyDisabled
                $ConfigObject.ConfigWontApply=$ConfigWontApply
                $ConfigObject.ConfigReadonly=$Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()

                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,[ORCAResult]::Pass)

                $this.AddConfig($ConfigObject)

            }
        }        

    }

}
