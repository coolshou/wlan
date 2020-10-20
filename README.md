# wlan
wlan is the WindowsSDK sample for the WirelessAPI.


# require 
  vc2019 (v16.1.28922)
  Win10 SDK 10.0.18362 (1903)

# build wlan.exe, in cmd window run following command
```
  build.bat clean
  build.bat build
```

# feature
The following commands are available. Use "help xyz" to show the description of command xyz.
```
        EnumInterface(ei)
        GetDeviceList(gd)
        GetInterfaceList(gi)
        GetInterfaceCapability(gic)
        QueryInterface(qi)
        SetRadioState(srs)
        GetDriverStatistics(gds)
        Scan(scan)
        GetBssList(gbs)
        GetVisibleNetworkList(gvl)
        CreateProfile(cp)
        SetProfile(sp)
        SaveTempProfile(stp)
        GetProfile(gp)
        DeleteProfile(dp)
        DeleteProfileList(dpl)
        SetProfileList(spl)
        GetProfileList(gpl)
        Connect(conn)
        Disconnect(dc)
        Discover(disc)
        State(st)
        GetChannel(ch)
        GetBSSID(bssid)
        GetRSSI(rssi)
        ListRegkeys(lr)
        GetRegkeyValue(gr)
        SetRegkeyValue(sr)
        DisableInterface(disable)
        EnableInterface(enable)
        RegisterNotif(r)
        version(ver)
        help(?)
```
# reference
  https://msdn.microsoft.com/en-us/library/windows/desktop/ms706275(v=vs.85).aspx

# Note:
	Win10 1809(SDK 10.0.17763) add 11ax phy: "dot11_phy_type_he"
	Win10 1903(SDK 10.0.18362) add WPA3: DOT11_AUTH_ALGO_WPA3 & DOT11_AUTH_ALGO_WPA3_SAE
	Win10 2004(SDK 10.0.19041) add WPA3 Opportunistic Wireless Encryption: DOT11_AUTH_ALGO_OWE
