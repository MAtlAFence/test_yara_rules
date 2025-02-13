rule crazypig_rule
{
    strings:
        $ascii = "crazypig" ascii
        $utf16 = "crazypig" wide

    condition:
        any of them
}