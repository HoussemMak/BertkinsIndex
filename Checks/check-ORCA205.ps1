using module "..\ORCA.psm1"

class ORCA205 : ORCACheck
{
    <#
    
        CONSTRUCTOR with Check Header Data
    
    #>

    ORCA205()
    {
        $this.Control=205
        $this.Area=Get-LocalizedString -Key "ORCA205_Area"
        $this.Name=Get-LocalizedString -Key "ORCA205_Name"
        $this.PassText=Get-LocalizedString -Key "ORCA205_PassText"
        $this.FailRecommendation=Get-LocalizedString -Key "ORCA205_FailRecommendation"
        $this.Importance=Get-LocalizedString -Key "ORCA205_Importance"
        $this.ExpandResults=$True
        $this.CheckType=[CheckType]::ObjectPropertyValue
        $this.ObjectType=Get-LocalizedString -Key "ORCA205_ObjectType"
        $this.ItemName=Get-LocalizedString -Key "ORCA205_ItemName"
        $this.DataType=Get-LocalizedString -Key "ORCA205_DataType"
        $this.ChiValue=[ORCACHI]::Low
        $this.Links= @{
            (Get-LocalizedString -Key "ORCA205_Link_DefenderPortal")="https://security.microsoft.com/antimalwarev2"
            (Get-LocalizedString -Key "ORCA205_Link_ConfigurePolicy")="https://aka.ms/orca-mfp-docs-1"
            (Get-LocalizedString -Key "ORCA205_Link_RecommendedSettings")="https://aka.ms/orca-atpp-docs-6"
        }
    }

    <#
    
        RESULTS
    
    #>

    GetResults($Config)
    {

        $DefaultFileFormats = @("ace","ani", "apk", "app","appx", "arj", "bat", "cab", "cmd", "com", "deb", "dex", "dll", "docm", "elf", "exe", "hta", "img", "iso", "jar", "jnlp", "kext", "lha", "lib", "library", "lnk", "lzh", "macho", "msc", "msi", "msix", "msp", "mst", "pif", "ppa", "ppam", "reg", "rev", "scf", "scr", "sct", "sys", "uif", "vb", "vbe", "vbs", "vxd", "wsc", "wsf", "wsh", "xll", "xz", "z")
      
        ForEach($Policy in $Config["MalwareFilterPolicy"])
        {
            $IsPolicyDisabled = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
            $EnableFileFilter = $($Policy.EnableFileFilter)
            $policyname = $Config["PolicyStates"][$Policy.Guid.ToString()].Name

            # Fail if EnableFileFilter is not set to true or FileTypes is empty in the policy

            If($EnableFileFilter -eq $false) 
            {
                $ConfigObject = [ORCACheckConfig]::new()
                $ConfigObject.Object=$policyname
                $ConfigObject.ConfigItem="FileFilter"
                $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                $ConfigObject.ConfigReadonly = $Policy.IsPreset
                $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                $ConfigObject.ConfigData=$("EnableFileFilter Disabled")
                $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                $this.AddConfig($ConfigObject)
            }
            Else
            {
                # Enabled, check file types

                $MissingFiles = @();

                # Validate each file format
                foreach($DefaultFileFormat in $DefaultFileFormats)
                {
                    if($Policy.FileTypes -notcontains $DefaultFileFormat)
                    {
                        $MissingFiles += $DefaultFileFormat
                    }
                }

                if($MissingFiles.Count -eq 0)
                {
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="FileFilter"
                    $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                    $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                    $ConfigObject.ConfigReadonly = $Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                    $ConfigObject.ConfigData=$("Enabled with all default file types")
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Pass")
                    $this.AddConfig($ConfigObject)
                } else {
                    $ConfigObject = [ORCACheckConfig]::new()
                    $ConfigObject.Object=$policyname
                    $ConfigObject.ConfigItem="FileFilter"
                    $ConfigObject.ConfigDisabled = $Config["PolicyStates"][$Policy.Guid.ToString()].Disabled
                    $ConfigObject.ConfigWontApply = !$Config["PolicyStates"][$Policy.Guid.ToString()].Applies
                    $ConfigObject.ConfigReadonly = $Policy.IsPreset
                    $ConfigObject.ConfigPolicyGuid=$Policy.Guid.ToString()
                    $ConfigObject.ConfigData=$($MissingFiles -join ",")
                    $ConfigObject.SetResult([ORCAConfigLevel]::Standard,"Fail")
                    $this.AddConfig($ConfigObject)
                }
                
            }

            
        }
        
    }

}
