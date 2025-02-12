rule trojan_greenFiles_green: campaign
{
    meta:
    		rule_id = "3f9c9351-82f0-4aea-936f-b15d53987d1e"
        description = "Test rule to verify if it works on decrypted strings"
        package = "test.test.test"
        main_category = "Malware"
        sub_category = "Trojan"
        mitre_tactic = "Privilege Escalation"
        mitre_technique = "Exploitation for Privilege Escalation"
        mitre_id = "T1404"
        date_created = "2023-08-27"
        author = "Michael Atlas"
		
        
    strings:
  $test = "US5GTOSGZKJ5YZOIQKXVGIQ5KSUPO5UTKYOM5uTKyOMTGR2"
condition:
  all of them				
}
