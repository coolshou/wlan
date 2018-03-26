/*++
Copyright (c) 2006 Microsoft Corporation
Module Name:
    wlan.cpp
Abstract:
    Use WLAN APIs to control wireless device

Date:
	11/08/2005  created
    08/22/2006  modified
	05/02/2017  add 11n/11ac

Environment:
   User mode only
--*/
// define this flag for COM
#define _WIN32_DCOM

#include <WinSock2.h>
#include <windows.h>
#include <conio.h>
#include <objbase.h>
#include <rpcsal.h>
#include <objbase.h>
#include <msxml6.h>
#include <atlbase.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <atlstr.h>

#include <netioapi.h> //MIB_IF_TABLE2
#include <iphlpapi.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <string.h>

#include <setupapi.h> //EnableNetDevice
//#include <netcfgx.h>
#include <devguid.h>
#include <Ndisguid.h> //GUID_DEVINTERFACE_NET
// headers needed to use WLAN APIs 
#include <wlanapi.h>

#include "CommandError.h"				// CWin32ErrToWString
#include "version.h"

using namespace std;

// get win32 error from HRESULT
#define WIN32_FROM_HRESULT(hr)           \
    (SUCCEEDED(hr) ? ERROR_SUCCESS :    \
        (HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (hr)))

DWORD OSMajor;
//HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}
#define REG_NIC_PATH L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\"

// os version
typedef void (WINAPI *RtlGetVersion_FUNC)(OSVERSIONINFOEXW*);
BOOL GetVersion2(OSVERSIONINFOEX* os) {
	HMODULE hMod;
	RtlGetVersion_FUNC func;
#ifdef UNICODE
	OSVERSIONINFOEXW* osw = os;
#else
	OSVERSIONINFOEXW o;
	OSVERSIONINFOEXW* osw = &o;
#endif

	hMod = LoadLibrary(TEXT("ntdll.dll"));
	if (hMod) {
		func = (RtlGetVersion_FUNC)GetProcAddress(hMod, "RtlGetVersion");
		if (func == 0) {
			FreeLibrary(hMod);
			return FALSE;
		}
		ZeroMemory(osw, sizeof(*osw));
		osw->dwOSVersionInfoSize = sizeof(*osw);
		func(osw);
#ifndef	UNICODE
		os->dwBuildNumber = osw->dwBuildNumber;
		os->dwMajorVersion = osw->dwMajorVersion;
		os->dwMinorVersion = osw->dwMinorVersion;
		os->dwPlatformId = osw->dwPlatformId;
		os->dwOSVersionInfoSize = sizeof(*os);
		DWORD sz = sizeof(os->szCSDVersion);
		WCHAR* src = osw->szCSDVersion;
		unsigned char* dtc = (unsigned char*)os->szCSDVersion;
		while (*src)
			*dtc++ = (unsigned char)*src++;
		*dtc = '¥0';
#endif

	}
	else
		return FALSE;
	FreeLibrary(hMod);
	return TRUE;
}

//
// Register functions
//

//SetKeyData(HKEY_LOCAL_MACHINE, “Software\\Microsoft\\Windows\\CurrentVersion\\Run”, REG_SZ, “ApplicationName”, “C:\\ApplicationPath\\ApplicationName.exe”, strlen(“C:\\ApplicationPath\\ApplicationName.exe”));
int 
SetKeyData(HKEY hRootKey, LPCWSTR subKey, DWORD dwType, LPCWSTR value, LPBYTE data, DWORD cbData)
{
    HKEY hKey;
    int rc;
    if(RegCreateKey(hRootKey, subKey, &hKey) != ERROR_SUCCESS)
        return 0;
    //Require administrator right to read/write register key
    rc = RegSetValueEx(hKey, value, 0, dwType, data, cbData);
    if( rc != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return rc;
    }
    RegCloseKey(hKey);
    return 1;
}
//GetKeyData(HKEY_LOCAL_MACHINE, “Software\\Microsoft\\Windows\\CurrentVersion\\Run”, “ApplicationName”, storeHere, strlen(storeHere));
int GetKeyData(HKEY hRootKey, LPCWSTR subKey, LPCWSTR value, LPBYTE data, DWORD cbData)
{
    HKEY hKey;
    int rc;
    if(RegOpenKeyEx(hRootKey, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return 0;
    rc = RegQueryValueEx(hKey, value, NULL, NULL, data, &cbData);
    if( rc != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return rc;
    }
    RegCloseKey(hKey);
    return 1;
}
//
#define BYTES_PER_DWORD 4
void DwordsToBytesArray(const DWORD *dwIn, BYTE *bOut, const UINT dwCount,
    const UINT bCount){
  UINT i = 0, j = 0, k = 0, l = 0;
  BYTE bBuff[BYTES_PER_DWORD];
  
  for(i = 0; i < dwCount; i++){
    *(DWORD*)bBuff = dwIn[i];
    for(k = BYTES_PER_DWORD; k > 0; k--){
      if(j < bCount){
        bOut[j++] = bBuff[k - 1];
      }
      else{
        break;
      }
    }
  }
}

void BytesArrayToString(const BYTE *bIn, char *strOut, const UINT bLen)
{
  UINT i = 0;
  for(i = 0; i < bLen; i++){
    strOut[i] = bIn[i];
  }
  strOut[bLen] = '\0';
}
//
// Utility functions
//

// get interface state string
LPWSTR
GetInterfaceStateString(
    __in WLAN_INTERFACE_STATE wlanInterfaceState
)
{
    LPWSTR strRetCode;

    switch(wlanInterfaceState)
    {
        case wlan_interface_state_not_ready:
            strRetCode = L"\"not ready\"";
            break;
        case wlan_interface_state_connected:
            strRetCode = L"\"connected\"";
            break;
        case wlan_interface_state_ad_hoc_network_formed:
            strRetCode = L"\"ad hoc network formed\"";
            break;
        case wlan_interface_state_disconnecting:
            strRetCode = L"\"disconnecting\"";
            break;
        case wlan_interface_state_disconnected:
            strRetCode = L"\"disconnected\"";
            break;
        case wlan_interface_state_associating:
            strRetCode = L"\"associating\"";
            break;
        case wlan_interface_state_discovering:
            strRetCode = L"\"discovering\"";
            break;
        case wlan_interface_state_authenticating:
            strRetCode = L"\"authenticating\"";
            break;
        default:
            strRetCode = L"\"invalid interface state\"";
    }

    return strRetCode;
}

// get ACM notification string
LPWSTR
GetAcmNotificationString(
    __in DWORD acmNotif
)
{
    LPWSTR strRetCode;

    switch(acmNotif)
    {
        case wlan_notification_acm_autoconf_enabled:
            strRetCode = L"\"autoconf enabled\"";
            break;
        case wlan_notification_acm_autoconf_disabled:
            strRetCode = L"\"autoconf disabled\"";
            break;
        case wlan_notification_acm_background_scan_enabled:
            strRetCode = L"\"background scan enabled\"";
            break;
        case wlan_notification_acm_background_scan_disabled:
            strRetCode = L"\"background scan disabled\"";
            break;
        case wlan_notification_acm_power_setting_change:
            strRetCode = L"\"power setting change\"";
            break;
        case wlan_notification_acm_scan_complete:
            strRetCode = L"\"scan complete\"";
            break;
        case wlan_notification_acm_scan_fail:
            strRetCode = L"\"scan fail\"";
            break;
        case wlan_notification_acm_connection_start:
            strRetCode = L"\"connection start\"";
            break;
        case wlan_notification_acm_connection_complete:
            strRetCode = L"\"connection complete\"";
            break;
        case wlan_notification_acm_connection_attempt_fail:
            strRetCode = L"\"connection fail\"";
            break;
        case wlan_notification_acm_filter_list_change:
            strRetCode = L"\"filter list change\"";
            break;
        case wlan_notification_acm_interface_arrival:
            strRetCode = L"\"interface arrival\"";
            break;
        case wlan_notification_acm_interface_removal:
            strRetCode = L"\"interface removal\"";
            break;
        case wlan_notification_acm_profile_change:
            strRetCode = L"\"profile change\"";
            break;
        case wlan_notification_acm_profiles_exhausted:
            strRetCode = L"\"profiles exhausted\"";
            break;
        case wlan_notification_acm_network_not_available:
            strRetCode = L"\"network not available\"";
            break;
        case wlan_notification_acm_network_available:
            strRetCode = L"\"network available\"";
            break;
        case wlan_notification_acm_disconnecting:
            strRetCode = L"\"disconnecting\"";
            break;
        case wlan_notification_acm_disconnected:
            strRetCode = L"\"disconnected\"";
            break;
        case wlan_notification_acm_adhoc_network_state_change:
            strRetCode = L"\"ad hoc network state changes\"";
            break;
        default:
            strRetCode = L"\"unknown ACM notification\"";
    }

    return strRetCode;
}

// get MSMM notification string
LPWSTR
GetMsmNotificationString(
    __in DWORD msmNotif
)
{
    LPWSTR strRetCode;

    switch(msmNotif)
    {
        case wlan_notification_msm_associating:
            strRetCode = L"\"associating\"";
            break;
        case wlan_notification_msm_associated:
            strRetCode = L"\"associated\"";
            break;
        case wlan_notification_msm_authenticating:
            strRetCode = L"\"authenticating\"";
            break;
        case wlan_notification_msm_connected:
            strRetCode = L"\"connected\"";
            break;
        case wlan_notification_msm_roaming_start:
            strRetCode = L"\"roaming start\"";
            break;
        case wlan_notification_msm_roaming_end:
            strRetCode = L"\"roaming end\"";
            break;
        case wlan_notification_msm_radio_state_change:
            strRetCode = L"\"radio state change\"";
            break;
        case wlan_notification_msm_signal_quality_change:
            strRetCode = L"\"signal quality change\"";
            break;
        case wlan_notification_msm_disassociating:
            strRetCode = L"\"disassociating\"";
            break;
        case wlan_notification_msm_disconnected:
            strRetCode = L"\"disconnected\"";
            break;
        case wlan_notification_msm_peer_join:
            strRetCode = L"\"a peer joins the ad hoc network\"";
            break;
        case wlan_notification_msm_peer_leave:
            strRetCode = L"\"a peer leaves the ad hoc network\"";
            break;
        case wlan_notification_msm_adapter_removal:
            strRetCode = L"\"adapter is in a bad state\"";
            break;
        default:
            strRetCode = L"\"unknown MSM notification\"";
    }

    return strRetCode;
}

// get connection mode string
LPWSTR
GetConnectionModeString(
    __in WLAN_CONNECTION_MODE wlanConnMode
)
{
    LPWSTR strRetCode;

    switch(wlanConnMode)
    {
        case wlan_connection_mode_profile:
            strRetCode = L"\"manual connection with a profile\"";
            break;
        case wlan_connection_mode_temporary_profile:
            strRetCode = L"\"manual connection with a temporary profile\"";
            break;
        case wlan_connection_mode_discovery_secure:
            strRetCode = L"\"connection to a secure network without a profile\"";
            break;
        case wlan_connection_mode_discovery_unsecure:
            strRetCode = L"\"connection to an unsecure network without a profile\"";
            break;
        case wlan_connection_mode_auto:
            strRetCode = L"\"automatic connection with a profile\"";
            break;
        default:
            strRetCode = L"\"invalid connection mode\"";
    }

    return strRetCode;
}

// get PHY type string
LPWSTR 
GetPhyTypeString(
    __in ULONG uDot11PhyType
)
{
    LPWSTR strRetCode;

    switch(uDot11PhyType)
    {
		case dot11_phy_type_any:
			strRetCode = L"\"any\"";
			break;
		case dot11_phy_type_fhss:
			strRetCode = L"\"FHSS\"";
			break;
		case dot11_phy_type_dsss:
            strRetCode = L"\"DSSS\"";
            break;
		case dot11_phy_type_irbaseband:
			strRetCode = L"\"IR-base band\"";
			break;
		case dot11_phy_type_ofdm:
			strRetCode = L"\"802.11a\"";
			break;
		case dot11_phy_type_hrdsss:
			strRetCode = L"\"802.11b\"";
			break;
		case dot11_phy_type_erp:
            strRetCode = L"\"802.11g\"";
            break;
		case dot11_phy_type_ht:
			strRetCode = L"\"802.11n\"";
			break;
		case dot11_phy_type_vht:
			strRetCode = L"\"802.11ac\"";
			break;
        default:
            strRetCode = L"\"Unknown PHY type\"";
    }

    return strRetCode;
}

// get BSS type string
LPWSTR 
GetBssTypeString(
    __in DOT11_BSS_TYPE dot11BssType
)
{
    LPWSTR strRetCode;

    switch(dot11BssType)
    {
        case dot11_BSS_type_infrastructure:
            strRetCode = L"\"Infrastructure\"";
            break;
        case dot11_BSS_type_independent:
            strRetCode = L"\"Ad hoc\"";
            break;
        case dot11_BSS_type_any:
            strRetCode = L"\"Any\"";
            break;
        default:
            strRetCode = L"\"Unknown BSS type\"";
    }

    return strRetCode;
}

// get radio state string
LPWSTR
GetRadioStateString(
    __in DOT11_RADIO_STATE radioState
)
{
    LPWSTR strRetCode;

    switch(radioState)
    {
        case dot11_radio_state_on:
            strRetCode = L"\"on\"";
            break;
        case dot11_radio_state_off:
            strRetCode = L"\"off\"";
            break;
        default:
            strRetCode = L"\"unknown state\"";
    }

    return strRetCode;
}


// get auth algorithm string
LPWSTR 
GetAuthAlgoString(
    __in DOT11_AUTH_ALGORITHM dot11AuthAlgo
)
{
    LPWSTR strRetCode = L"\"Unknown algorithm\"";

    switch(dot11AuthAlgo)
    {
        case DOT11_AUTH_ALGO_80211_OPEN:
            strRetCode = L"\"Open\"";
            break;
        case DOT11_AUTH_ALGO_80211_SHARED_KEY:
            strRetCode = L"\"Shared\"";
            break;
        case DOT11_AUTH_ALGO_WPA:
            strRetCode = L"\"WPA-Enterprise\"";
            break;
        case DOT11_AUTH_ALGO_WPA_PSK:
            strRetCode = L"\"WPA-Personal\"";
            break;
        case DOT11_AUTH_ALGO_WPA_NONE:
            strRetCode = L"\"WPA-NONE\"";
            break;
        case DOT11_AUTH_ALGO_RSNA:
            strRetCode = L"\"WPA2-Enterprise\"";
            break;
        case DOT11_AUTH_ALGO_RSNA_PSK:
            strRetCode = L"\"WPA2-Personal\"";
            break;
        default:
            if (dot11AuthAlgo & DOT11_AUTH_ALGO_IHV_START)
            {
                strRetCode = L"\"Vendor-specific algorithm\"";
            }
    }

    return strRetCode;
}

// get cipher algorithm string
LPWSTR 
GetCipherAlgoString(
    __in DOT11_CIPHER_ALGORITHM dot11CipherAlgo
)
{
    LPWSTR strRetCode = L"\"Unknown algorithm\"";

    switch(dot11CipherAlgo)
    {
        case DOT11_CIPHER_ALGO_NONE:
            strRetCode = L"\"None\"";
            break;
        case DOT11_CIPHER_ALGO_WEP40:
            strRetCode = L"\"WEP40\"";
            break;
        case DOT11_CIPHER_ALGO_TKIP:
            strRetCode = L"\"TKIP\"";
            break;
        case DOT11_CIPHER_ALGO_CCMP:
            strRetCode = L"\"AES\"";
            break;
        case DOT11_CIPHER_ALGO_WEP104:
            strRetCode = L"\"WEP104\"";
            break;
        case DOT11_CIPHER_ALGO_WPA_USE_GROUP:
            strRetCode = L"\"USE-GROUP\"";
            break;
        case DOT11_CIPHER_ALGO_WEP:
            strRetCode = L"\"WEP\"";
            break;
        default:
            if (dot11CipherAlgo & DOT11_CIPHER_ALGO_IHV_START)
            {
                strRetCode = L"\"Vendor-specific algorithm\"";
            }
    }

    return strRetCode;
}
//get BSSID from the WCHAR string
/*strBssid: 00:11:22:33:44:55
//          00-11-22-33-44-55
*/
DWORD StringWToBSSID(
	__in string strBssid,
	__out uint8_t *results
//	__out vector<string>* results
)
{
	DWORD dwRetCode = ERROR_SUCCESS;
	BYTE pbSsid[DOT11_SSID_MAX_LENGTH + 1] = { 0 };

	if (strBssid.empty()  || results == NULL)
	{
		dwRetCode = ERROR_INVALID_PARAMETER;
	}
	else
	{
		//TODO: check strBssid format
		// parser strBssid
		string separator = ":";
		//int found;
		size_t found;
		found = strBssid.find_first_of(separator);
		while (found != string::npos) {
			if (found > 0) {
				//results->push_back(strBssid.substr(0, found));
			}
			strBssid = strBssid.substr(found + 1);
			found = strBssid.find_first_of(separator);
		}
		if (strBssid.length() > 0) {
			//results->push_back(strBssid);
		}
	}
	return dwRetCode;
}
// get SSID from the WCHAR string
DWORD
StringWToSsid(
    __in LPCWSTR strSsid, 
    __out PDOT11_SSID pSsid
)
{
    DWORD dwRetCode = ERROR_SUCCESS;
    BYTE pbSsid[DOT11_SSID_MAX_LENGTH + 1] = {0};

    if (strSsid == NULL || pSsid == NULL)
    {
        dwRetCode = ERROR_INVALID_PARAMETER;
    }
    else
    {
        pSsid->uSSIDLength = WideCharToMultiByte (CP_ACP,
                                                   0,
                                                   strSsid,
                                                   -1,
                                                   (LPSTR)pbSsid,
                                                   sizeof(pbSsid),
                                                   NULL,
                                                   NULL);

        pSsid->uSSIDLength--;
        memcpy(&pSsid->ucSSID, pbSsid, pSsid->uSSIDLength);
    }

    return dwRetCode;
}

// copy SSID to a null-terminated WCHAR string
// count is the number of WCHAR in the buffer.
LPWSTR
SsidToStringW(
    __out_ecount(count) LPWSTR   buf,
    __in ULONG   count,
    __in PDOT11_SSID pSsid
    )
{
    ULONG   bytes, i;

    bytes = min( count-1, pSsid->uSSIDLength);
    for( i=0; i<bytes; i++)
        mbtowc( &buf[i], (const char *)&pSsid->ucSSID[i], 1);
    buf[bytes] = '\0';

    return buf;
}


// the max lenght of the reason string in characters
#define WLSAMPLE_REASON_STRING_LEN 256

// print the reason string
VOID
PrintReason(
    __in WLAN_REASON_CODE reason
)
{
    WCHAR strReason[WLSAMPLE_REASON_STRING_LEN];

    if (WlanReasonCodeToString(
            reason, 
            WLSAMPLE_REASON_STRING_LEN,
            strReason, 
            NULL            // reserved
            ) == ERROR_SUCCESS)
    {
        wcout << L" The reason is \"" << strReason << L"\"." << endl;
    }
    else
    {
        wcout << L" The reason code is " << reason << L"." << endl;
    }
}

// print the basic information of a visible wireless network
VOID PrintNetworkInfo(
    __in PWLAN_AVAILABLE_NETWORK pNetwork
)
{
    WCHAR strSsid[DOT11_SSID_MAX_LENGTH+1];

    if (pNetwork != NULL)
    {
        // SSID
        wcout << L"SSID: " << SsidToStringW(strSsid, sizeof(strSsid)/sizeof(WCHAR), &pNetwork->dot11Ssid) << endl;

        // whether security is enabled
        if (pNetwork->bSecurityEnabled)
        {
            wcout << L"\tSecurity enabled." << endl;
        }
        else
        {
            wcout << L"\tSecurity not enabled." << endl;
        }

        // number of BSSIDs //TODO: list all BSSID
        wcout << L"\tContains " << pNetwork->uNumberOfBssids << L" BSSIDs." << endl;

        // whether have a profile for this SSID
        if (pNetwork->dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE)
        {
            wcout << L"\tHas a matching profile: " << pNetwork->strProfileName << L"." <<endl;
        }

        // whether it is connected
        if (pNetwork->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)
        {
            wcout << L"\tCurrently connected." << endl;
        }

        // whether it is connectable
        if (!pNetwork->bNetworkConnectable)
        {
            // the reason that it is not connectable
            wcout << L"\tThe network is not connectable. ";
            PrintReason(pNetwork->wlanNotConnectableReason);
        }
        else
        {
            wcout << L"\tThe network is connectable." << endl;
        }

        // BSS type
        wcout << L"\tBSS type: " << GetBssTypeString(pNetwork->dot11BssType) << endl;
        
        // Signal quality
        wcout << L"\tSignal quality: " << pNetwork->wlanSignalQuality << L"%" << endl;

        // Default auth algorithm
        wcout << L"\tDefault authentication algorithm: " << GetAuthAlgoString(pNetwork->dot11DefaultAuthAlgorithm) << endl;

        // Default cipher algorithm
        wcout << L"\tDefault cipher algorithm: " << GetCipherAlgoString(pNetwork->dot11DefaultCipherAlgorithm) << endl;
    }
}

// get BSSID string
char*
GetBssidString(
	__in DOT11_MAC_ADDRESS Bssid
)
{
	static char str[18];
	// MAC address
	snprintf(str, sizeof(str), "%02X:%02X:%02X:%02X:%02X:%02X",
		Bssid[0], Bssid[1], Bssid[2], Bssid[3], Bssid[4], Bssid[5]);
	return str;
}

// print BSS info
VOID 
PrintBssInfo(
    __in PWLAN_BSS_ENTRY pBss
)
{
    WCHAR strSsid[DOT11_SSID_MAX_LENGTH+1];
    UINT i;
    PBYTE pIe = NULL;
    
    if (pBss != NULL)
    {
		//col mode, use \t to sepelate
		//MAC SSID CenterFrequency RSSI LinkQuality phyType
		wcout << GetBssidString(pBss->dot11Bssid);
		wcout << L"\t";
		wcout << SsidToStringW(strSsid, sizeof(strSsid) / sizeof(WCHAR), &pBss->dot11Ssid);
		wcout << L"\t";
		wcout << pBss->ulChCenterFrequency/1000;
		wcout << L"\t";
		wcout << pBss->lRssi;
		wcout << L"\t";
		wcout << pBss->uLinkQuality;
		wcout << L"\t";
		wcout << GetPhyTypeString(pBss->dot11BssPhyType);
		/*
		//https://msdn.microsoft.com/en-us/library/windows/desktop/aa370026(v=vs.85).aspx
		//wcout << pBss->wlanRateSet;
		*/
		wcout << L"\t";
		wcout << endl;
		if (0) {
        // MAC address
        wcout << L"MAC address: ";
		wcout << GetBssidString(pBss->dot11Bssid);
		wcout << endl;
        // SSID
        wcout << L"\tSSID: " << SsidToStringW(strSsid, sizeof(strSsid)/sizeof(WCHAR), &pBss->dot11Ssid) << endl;

        // Beacon period
        wcout << L"\tBeacon period: " << dec << pBss->usBeaconPeriod << L" TU" << endl;
        
        // IE , TODO: parser IE for MU MIMO/TxBF....
		if (0) {
			wcout << L"\tIE";
			i = 0;
			pIe = (PBYTE)(pBss)+pBss->ulIeOffset;

			// print 8 byte per line
			while (i < pBss->ulIeSize)
			{
				if (i % 8 == 0)
				{
					wcout << endl << L"\t\t";
				}
				wcout << setw(2) << setfill(L'0') << hex << (UINT)pIe[i] << L" ";
				i++;
			}
		}
        wcout << endl;
    }
    }
    
}

#define WLAN_INVALID_COUNTER (ULONGLONG)-1

// print the counter value in driver statistics
VOID 
PrintCounterValue(
    __in ULONGLONG value
)
{
    if (value == WLAN_INVALID_COUNTER)
        wcout << L" cannot be obtained" << endl;
    else
        // wcout cannot handle ULONGLONG
        wcout << (UINT)value << endl;
}

// print the error message
VOID
PrintErrorMsg(
    __in LPWSTR strCommand,
    __in DWORD dwError
)
{
    if (strCommand != NULL)
    {
        if (dwError == ERROR_SUCCESS)
        {
            wcout << L"Command \"" << strCommand << L"\" completed successfully." << endl;
        }
        else if (dwError == ERROR_INVALID_PARAMETER)
        {
            wcout << L"The parameter for \"" << strCommand << L"\" is not correct. ";
            wcout << L"Please use \"help " << strCommand << L"\" to check the usage of the command." << endl;
        }
        else if (dwError == ERROR_BAD_PROFILE)
        {
            wcout << L"The given profile is not valid." << endl;
        }
        else if (dwError == ERROR_NOT_SUPPORTED)
        {
            wcout << L"Command \"" << strCommand << L"\" is not supported." << endl;
        }
        else
        {
            wcout << L"Got error " << dwError << L" for command \"" << strCommand << L"\"" << endl;
        }
    }
}

// open a WLAN client handle and check version
DWORD
OpenHandleAndCheckVersion(
    PHANDLE phClient
)
{
    DWORD dwError = ERROR_SUCCESS;
    DWORD dwServiceVersion;
    HANDLE hClient = NULL;

    __try
    {
        *phClient = NULL;
        
        // open a handle to the service
        if ((dwError = WlanOpenHandle(
                            WLAN_API_VERSION,
                            NULL,               // reserved
                            &dwServiceVersion,
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // check service version
        if (WLAN_API_VERSION_MAJOR(dwServiceVersion) < WLAN_API_VERSION_MAJOR(WLAN_API_VERSION_2_0))
        {
            // No-op, because the version check is for demonstration purpose only.
            // You can add your own logic here.
        }

        *phClient = hClient;

        // set hClient to NULL so it will not be closed
        hClient = NULL;
    }
    __finally
    {
        if (hClient != NULL)
        {
            // clean up
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    return dwError;
}

//
// Functions that demonstrate how to use WLAN APIs
//

// Notification callback function
VOID WINAPI
NotificationCallback(
    __in PWLAN_NOTIFICATION_DATA pNotifData, 
    __in_opt PVOID pContext  // this parameter is not used
)
{
    WCHAR strSsid[DOT11_SSID_MAX_LENGTH+1];
    PWLAN_CONNECTION_NOTIFICATION_DATA pConnNotifData = NULL;

    if (pNotifData != NULL)
    {
        switch(pNotifData->NotificationSource)
        {
            case WLAN_NOTIFICATION_SOURCE_ACM:
                wcout << L"Got notification " << GetAcmNotificationString(pNotifData->NotificationCode) << L" from ACM." << endl; 

                // print some notifications as examples
                switch(pNotifData->NotificationCode)
                {
                    case wlan_notification_acm_connection_complete:
                        if (pNotifData->dwDataSize < sizeof(WLAN_CONNECTION_NOTIFICATION_DATA))
                        {
                            break;
                        }
                        pConnNotifData = (PWLAN_CONNECTION_NOTIFICATION_DATA)pNotifData->pData;
                        if (pConnNotifData->wlanReasonCode == WLAN_REASON_CODE_SUCCESS)
                        {
                            wcout << L"The connection succeeded." << endl;

                            if (pConnNotifData->wlanConnectionMode == wlan_connection_mode_discovery_secure ||
                                pConnNotifData->wlanConnectionMode == wlan_connection_mode_discovery_unsecure)
                            {
                                // the temporary profile generated for discovery
                                wcout << L"The profile used for this connection is as follows:" << endl;
                                wcout << pConnNotifData->strProfileXml << endl;
                            }
                        }
                        else
                        {
                            wcout << L"The connection failed.";
                            PrintReason(pConnNotifData->wlanReasonCode);
                        }
                        break;
                    case wlan_notification_acm_connection_start:
                        if (pNotifData->dwDataSize != sizeof(WLAN_CONNECTION_NOTIFICATION_DATA))
                        {
                            break;
                        }
                        pConnNotifData = (PWLAN_CONNECTION_NOTIFICATION_DATA)pNotifData->pData;
                        // print out some connection information
                        wcout << L"\tCurrently connecting to " << SsidToStringW(strSsid, sizeof(strSsid)/sizeof(WCHAR), &pConnNotifData->dot11Ssid);
        
                        wcout << L" using profile " << pConnNotifData->strProfileName;
                        wcout << L", connection mode is " << GetConnectionModeString(pConnNotifData->wlanConnectionMode);
                        wcout << L", BSS type is " << GetBssTypeString(pConnNotifData->dot11BssType) << endl;

                        break;
                }

                break;
            case WLAN_NOTIFICATION_SOURCE_MSM:
                wcout << L"Got notification " << GetMsmNotificationString(pNotifData->NotificationCode) << L" from MSM." << endl; 
                break;
        }

    }
}

// Register for notification
DWORD
RegisterNotification(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    DWORD dwPrevNotifType = 0;

    __try
    {
        if (argc != 1)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open a handle to the service
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // register for ACM and MSM notifications
        if ((dwError = WlanRegisterNotification(
                            hClient,
                            WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM,
                            FALSE,			// do not ignore duplications
                            NotificationCallback,
                            NULL,			// no callback context is needed
                            NULL,           // reserved
                            &dwPrevNotifType
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        wcout << L"ACM and MSM notifications are successfully registered. Press any key to exit." << endl;

        // wait for the user to press a key
        _getch();

        // unregister notifications
        if ((dwError = WlanRegisterNotification(
                            hClient,
                            WLAN_NOTIFICATION_SOURCE_NONE,
                            FALSE,          // do not ignore duplications
                            NULL,           // no callback function is needed
                            NULL,           // no callback context is needed
                            NULL,           // reserved
                            &dwPrevNotifType
                            )) == ERROR_SUCCESS)
        {
            wcout << L"ACM and MSM notifications are successfully unregistered." << endl;
        }
        else
        {
            wcout << L"Error " << dwError << L" occurs when unresiger ACM and MSM notifications." << endl;
        }
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// Create Profile
//<interface GUID> <SSID> <OPEN|WEP|SHARED|WPAPSK|WPA2PSK> <WEP|TKIP|AES> <KEY>
DWORD
CreateProfile(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	DWORD dwReason;
	HANDLE hClient = NULL;
	GUID guidIntf;
	DOT11_SSID dot11Ssid = { 0 };
	PDOT11_SSID pDot11Ssid = NULL;
	LPWSTR ssid;

	LPWSTR authType;
	LPWSTR key;

	LPWSTR cipherType;
	//LPCWSTR profileXml;
	wstring profileXml = L"";

	// __try and __leave cannot be used here
	do
	{
		if (argc < 4)
		{
			dwError = ERROR_INVALID_PARAMETER;
			break;
		}
		// get the interface GUID
		if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
		{
			wcerr << L"Invalid GUID " << argv[1] << endl;
			dwError = ERROR_INVALID_PARAMETER;
			break;
		}
		//TODO: check SSID length
		ssid = argv[2];
		wstring wSsid(ssid);
		//convert to HEX string
		std::wstringstream hSsid;
		for (u_int i = 0;i< wSsid.length();i++) {
			hSsid << std::hex << (int)wSsid.at(i);
		}
		//
		authType = argv[3];

		if (argc >= 4) {
			cipherType = argv[4];
		}

		if (argc >= 5) {
			key = argv[5];
		}

		profileXml += L"<?xml version=\"1.0\"?>";
		profileXml += L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">";
		profileXml += L"<name>"+ wSsid + L"</name>";
		profileXml += L"<SSIDConfig>";
		profileXml += L"<SSID>";
		profileXml += L"<hex>" + hSsid.str() + L"</hex>";
		profileXml += L"<name>" + wSsid + L"</name>";
		profileXml += L"</SSID>";
		profileXml += L"<nonBroadcast>true</nonBroadcast>"; //TODO:
		profileXml += L"</SSIDConfig>";
		profileXml += L"<connectionType>ESS</connectionType>";
		profileXml += L"<connectionMode>auto</connectionMode>"; //TODO:
		profileXml += L"<autoSwitch>false</autoSwitch>"; //TODO:
		profileXml += L"<MSM><security>";

		if ((wcscmp(authType, L"OPEN") == 0) || (wcscmp(authType, L"WEP") == 0)) {
			profileXml += L"<authEncryption>";
			profileXml += L"<authentication>open</authentication>";
			profileXml += L"<encryption>";
			if (wcscmp(authType, L"OPEN") == 0) {
				profileXml += L"none";
			}
			if (wcscmp(authType, L"WEP") == 0) {
				profileXml += L"WEP";
			}
			profileXml += L"</encryption>";
			profileXml += L"<useOneX>false</useOneX>";
			profileXml += L"</authEncryption>";
			if (wcscmp(authType, L"WEP") == 0) {
				profileXml += L"<sharedKey>";
				profileXml += L"<keyType>networkKey</keyType>";
				profileXml += L"<protected>false</protected>";
				wstring wKey(key);
				//TODO: key length check: 5, 10, 13, 26
				profileXml += L"<keyMaterial>" + wKey + L"</keyMaterial>";
				profileXml += L"</sharedKey>";
				//profileXml += L"<keyIndex>0</keyIndex>";
			}

		}	
		else if ((wcscmp(authType, L"WPAPSK") == 0)|| (wcscmp(authType, L"WPA2PSK") == 0)) {
			profileXml += L"<authEncryption>";
			profileXml += L"<authentication>";
			if (wcscmp(authType, L"WPAPSK") == 0) {
				profileXml += L"WPAPSK";
			}
			if (wcscmp(authType, L"WPA2PSK") == 0) {
				profileXml += L"WPA2PSK";
			}
			profileXml += L"</authentication>";
			profileXml += L"<encryption>";
			if (wcscmp(cipherType, L"TKIP") == 0) {
				profileXml += L"TKIP";
			}
			if (wcscmp(cipherType, L"AES") == 0) {
				profileXml += L"AES";
			}
			profileXml += L"</encryption>";
			profileXml += L"<useOneX>false</useOneX>";
			profileXml += L"</authEncryption>";
			profileXml += L"<sharedKey>";
			profileXml += L"<keyType>passPhrase</keyType>";
			profileXml += L"<protected>false</protected>";
			wstring wKey(key);
			//TODO: key length check: 8~64
			profileXml += L"<keyMaterial>" + wKey + L"</keyMaterial>";
			profileXml += L"</sharedKey>";
		}
		else {
			wcerr << L"Invalid authentication type: " << authType << endl;
			dwError = ERROR_INVALID_PARAMETER;
			break;
		}
		profileXml += L"</security></MSM>";
		profileXml += L"</WLANProfile>";
		
		//wcout << "=profile================================" << endl;
		//wcout << profileXml.c_str() << endl;
		//wcout << "========================================" << endl;
		
		// open a handle to the service
		if ((dwError = OpenHandleAndCheckVersion(
			&hClient
		)) != ERROR_SUCCESS)
		{
			break;
		}
		// set profile
		dwError = WlanSetProfile(
			hClient,
			&guidIntf,
			0,          // no flags for the profile 
			profileXml.c_str(),
			NULL,       // use the default ACL
			TRUE,		// overwrite a profile if it already exists
			NULL,       // reserved
			&dwReason
		);
		if (dwError == ERROR_BAD_PROFILE)
		{
			wcout << L"The profile is bad.";
			PrintReason(dwReason);
		}
	} while (FALSE);
	 
	// clean up
	if (hClient != NULL)
	{
		WlanCloseHandle(
			hClient,
			NULL            // reserved
		);
	}
	
	PrintErrorMsg(argv[0], dwError);
	return dwError;
}
// set profile
DWORD
SetProfile(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError;
    HRESULT hr;
    HANDLE hClient = NULL;
    GUID guidIntf;
    CComPtr<IXMLDOMDocument2> pXmlDoc;
    CComBSTR bstrXml;
    VARIANT_BOOL vbSuccess;
    DWORD dwReason;

	// __try and __leave cannot be used here because of COM object
    do
    {
        if (argc != 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            break;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            break;
        }

        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (hr != S_OK)
        {
            dwError = WIN32_FROM_HRESULT(hr);
            break;
        }
        
        // create a COM object to read the XML file
        hr = CoCreateInstance(
                CLSID_DOMDocument60,
                NULL,
                CLSCTX_INPROC_SERVER,
                IID_IXMLDOMDocument2,
                (void**)&pXmlDoc
                );
        if (hr != S_OK)
        {
            dwError = WIN32_FROM_HRESULT(hr);
            break;
        }
		
		// load the file into the COM object
		hr = pXmlDoc->load((CComVariant)argv[2], &vbSuccess);
        if (hr != S_OK || vbSuccess != VARIANT_TRUE)
        {
            dwError = ERROR_BAD_PROFILE;
            break;
        }

        // get XML string out from the file
        hr = pXmlDoc->get_xml(&bstrXml);
        if (hr != S_OK)
        {
            dwError = ERROR_BAD_PROFILE;
            break;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                                &hClient
                                )) != ERROR_SUCCESS)
        {
            break;
        }

        // set profile
        dwError = WlanSetProfile(
                            hClient, 
                            &guidIntf, 
                            0,          // no flags for the profile 
                            bstrXml, 
                            NULL,       // use the default ACL
                            TRUE,		// overwrite a profile if it already exists
                            NULL,       // reserved
                            &dwReason
                            );
        if (dwError == ERROR_BAD_PROFILE)
        {
            wcout << L"The profile is bad.";
            PrintReason(dwReason);
        }
    } while (FALSE);

    // clean up
    if (hClient != NULL)
    {
        WlanCloseHandle(
            hClient, 
            NULL            // reserved
            );
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// get profile
DWORD
GetProfile(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    PWSTR strXml;
    GUID guidIntf;
	DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
    __try
    {
        if (argc != 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // get profile
        if ((dwError = WlanGetProfile(
                            hClient, 
                            &guidIntf, 
                            argv[2],    // profile name
                            NULL,       // reserved
                            &strXml,    // XML string of the profile
							&dwFlags,       // retrieve the plain text key from a wireless profile
                            NULL        // don't care about ACL
                            )) == ERROR_SUCCESS)
        {
            wcout << L"The return profile xml is: " << endl << strXml << endl;
            WlanFreeMemory(strXml);
        }

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// delete profile
DWORD
DeleteProfile(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;

    __try
    {
        if (argc != 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        
        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // delete profile
        dwError = WlanDeleteProfile(
                        hClient, 
                        &guidIntf, 
                        argv[2],        // profile name
                        NULL            // reserved
                        );
		if (dwError != ERROR_SUCCESS) {
			wcerr << L"DeleteProfile failed on \"" << &guidIntf;
			wcerr << L"\" with error: " <<	dwError << endl;
			//TODO: use FormatMessage to find out why the function failed
		}
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// delete profile list (clear all profile)
DWORD
DeleteProfileList(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
) 
{
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hClient = NULL;
	GUID guidIntf;

	PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
	PWLAN_PROFILE_INFO pInfo = NULL;
	UINT i;

	__try
	{
		if (argc != 2)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}

		// get the interface GUID
		if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
		{
			wcerr << L"Invalid GUID " << argv[1] << endl;
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}


		// open handle
		if ((dwError = OpenHandleAndCheckVersion(
			&hClient
		)) != ERROR_SUCCESS)
		{
			__leave;
		}
		// get profile list
		if ((dwError = WlanGetProfileList(
			hClient,
			&guidIntf,
			NULL,               // reserved
			&pProfileList
		)) != ERROR_SUCCESS)
		{
			__leave;
		}

		wcout << L"There are " << pProfileList->dwNumberOfItems << L" profiles on the interface." << endl;
		// print out profiles
		for (i = 0; i < pProfileList->dwNumberOfItems; i++)
		{
			pInfo = &pProfileList->ProfileInfo[i];
			wcout << L"\t\"" << pInfo->strProfileName << L"\"" << endl;
			// delete profile
			dwError = WlanDeleteProfile(
				hClient,
				&guidIntf,
				pInfo->strProfileName,        // profile name
				NULL            // reserved
			);
			if (dwError != ERROR_SUCCESS) {
				wcerr << L"DeleteProfileList failed to delete \"" << pInfo->strProfileName; 
				wcerr << L"\" on interface \"" << &guidIntf;
				wcerr << L"\" with error: " << dwError << endl;
				//TODO: use FormatMessage to find out why the function failed
			}
		}
		

	}
	__finally
	{
		// clean up
		if (pProfileList != NULL) {
			WlanFreeMemory(pProfileList);
			pProfileList = NULL;
		}
		if (hClient != NULL)
		{
			WlanCloseHandle(
				hClient,
				NULL            // reserved
			);
		}
	}

	PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// set profile list
DWORD
SetProfileList(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;

    __try
    {
        if (argc < 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }
            
        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        // set profile list
        dwError = WlanSetProfileList(
                        hClient, 
                        &guidIntf, 
                        argc - 2,                   // number of profiles
                        (LPCWSTR *)(argv + 2),      // the list of profiles name following the command and the interface GUID
                        NULL                        // reserved
                        );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// get the list of profiles
DWORD
GetProfileList(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
    PWLAN_PROFILE_INFO pInfo = NULL;
    UINT i;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        

        // get profile list
        if ((dwError = WlanGetProfileList(
                            hClient, 
                            &guidIntf, 
                            NULL,               // reserved
                            &pProfileList
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        wcout << L"There are " << pProfileList->dwNumberOfItems << L" profiles on the interface." << endl;
        // print out profiles
        for (i = 0; i < pProfileList->dwNumberOfItems; i++)
        {
            pInfo = &pProfileList->ProfileInfo[i];
            wcout << L"\t\"" << pInfo->strProfileName << L"\"" << endl;
        }

    }
    __finally
    {
        // clean up
        if (pProfileList != NULL)
        {
            WlanFreeMemory(pProfileList);
        }
        
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// enumerate wireless interfaces
DWORD
EnumInterface(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    PWLAN_INTERFACE_INFO_LIST pIntfList = NULL;
    RPC_WSTR strGuid = NULL;
    UINT i = 0;

    __try
    {
        if (argc != 1)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // enumerate wireless interfaces
        if ((dwError = WlanEnumInterfaces(
                            hClient,
                            NULL,               // reserved
                            &pIntfList
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        wcout << L"There are " << pIntfList->dwNumberOfItems << L" interfaces in the system." << endl;

        // print out interface information
        for (i = 0; i < pIntfList->dwNumberOfItems; i++)
        {
			if (true) { //jimmy, change output format for easy parser, one line one device
				wcout << L"Interface " << i << L":";
				if (UuidToStringW(&pIntfList->InterfaceInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
				{
					wcout << L"\tGUID: " << (LPWSTR)strGuid ;
					//std::wstring temp = (LPWSTR)strGuid;
					//std::transform(temp.begin(), temp.end(), temp.begin(), ::toupper);
					//wcout << "\t" << temp;
					RpcStringFreeW(&strGuid);
				}
				wcout << L"\tNAME: " << pIntfList->InterfaceInfo[i].strInterfaceDescription << endl;
				//wcout << L"\tState: " << GetInterfaceStateString(pIntfList->InterfaceInfo[i].isState) << endl;
			}
			else {
				wcout << L"Interface " << i << L":" << endl;
				if (UuidToStringW(&pIntfList->InterfaceInfo[i].InterfaceGuid, &strGuid) == RPC_S_OK)
				{
					wcout << L"\tGUID: " << (LPWSTR)strGuid << endl;
					RpcStringFreeW(&strGuid);
				}
				wcout << L"\tNAME: " << pIntfList->InterfaceInfo[i].strInterfaceDescription << endl;
				wcout << L"\tState: " << GetInterfaceStateString(pIntfList->InterfaceInfo[i].isState) << endl;
				wcout << endl;
			}
        }
    }
    __finally
    {
        // clean up
        if (pIntfList != NULL)
        {
            WlanFreeMemory(pIntfList);
        }
        
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

//can not get disable net device
vector<MIB_IF_ROW2>* getDevices(NDIS_PHYSICAL_MEDIUM type)
{
	vector<MIB_IF_ROW2> *v = new vector<MIB_IF_ROW2>();
	PMIB_IF_TABLE2 table = NULL;
	if (GetIfTable2Ex(MibIfTableRaw, &table) == NOERROR && table)
	{
		UINT32 i = 0;
		for (; i < table->NumEntries; i++)
		{
			MIB_IF_ROW2 row;

			ZeroMemory(&row, sizeof(MIB_IF_ROW2));
			row.InterfaceIndex = i;
			if (GetIfEntry2(&row) == NOERROR)
			{
				if (row.PhysicalMediumType == type)
				{
					v->push_back(row);
				}
			}
		}
		FreeMibTable(table);
	}
	return v;
}


//This function will require Administrator
void EnableNetDevice(bool aState, int index)
{
	HDEVINFO NetPnPHandle;
	SP_PROPCHANGE_PARAMS PCHP;
	SP_DEVINFO_DATA DeviceData;
	RPC_WSTR strGuid = NULL;


	NetPnPHandle = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, 0, 0, DIGCF_PRESENT);
	//NetPnPHandle = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, 0, 0, DIGCF_DEVICEINTERFACE);
	//GUID_DEVCLASS_NET
	//GUID_DEVINTERFACE_NET
	if (NetPnPHandle == INVALID_HANDLE_VALUE)
	{
		return;
	}

	DeviceData.cbSize = sizeof(SP_DEVINFO_DATA);
	if (SetupDiEnumDeviceInfo(NetPnPHandle, index, &DeviceData)) {
		PCHP.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		wchar_t  szDesc[MAX_PATH] = { 0 };
		if (SetupDiGetClassDescription(&DeviceData.ClassGuid, szDesc, MAX_PATH, NULL)) {
			wcout << index << L": ClassDescription: " << szDesc << endl;
		}
		if (UuidToString(&DeviceData.ClassGuid, &strGuid) == RPC_S_OK)
		{
			wcout << index << L": ClassGuid: " << strGuid << endl;
		}
		wchar_t  szFriendlyName[MAX_PATH] = { 0 };
		if (SetupDiGetDeviceRegistryProperty(NetPnPHandle, &DeviceData,
			SPDRP_FRIENDLYNAME, 0L, (PBYTE)szFriendlyName, 2048, 0)) {
			wcout << index << L": FriendlyName: " << szFriendlyName << endl;
		}
		//why we need to call it here
		//SetupDiSetClassInstallParams(NetPnPHandle, &DeviceData, &PCHP.ClassInstallHeader, sizeof(SP_PROPCHANGE_PARAMS));
		
		PCHP.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		PCHP.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
		PCHP.HwProfile = 0;
		PCHP.Scope = DICS_FLAG_CONFIGSPECIFIC;
		if (aState) PCHP.StateChange = DICS_ENABLE;
		else  PCHP.StateChange = DICS_DISABLE;
		SetupDiSetClassInstallParams(NetPnPHandle, &DeviceData, &PCHP.ClassInstallHeader, sizeof(SP_PROPCHANGE_PARAMS));
		if (SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, NetPnPHandle, &DeviceData)) {
			wcout << L"EnableNetDevice: " << index << L" : " << aState << endl;
		}
		else {
			DWORD dwErr = GetLastError();
			std::wstring szErr = CWin32ErrToWString()(dwErr);
			wcout << L"ERROR: " << szErr << endl;
		}
			
	}
	else {
		wcout << L"SetupDiEnumDeviceInfo not found device: " << index << endl;
	}
	//DeviceData.cbSize = sizeof(SP_DEVINFO_DATA);
	SetupDiDestroyDeviceInfoList(NetPnPHandle);
}

DWORD
DisableInterface(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	LPWSTR sIdx;
	int idx;
	__try
	{
		if (argc != 2)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		sIdx = argv[1];
		idx = _wtoi(sIdx);
		EnableNetDevice(false, idx);
	}
	__finally
	{
		//
	}

	PrintErrorMsg(argv[0], dwError);
	return dwError;
}

DWORD
EnableInterface(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	LPWSTR sIdx;
	int idx;
	__try
	{
		if (argc != 2)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		sIdx = argv[1];
		idx = _wtoi(sIdx);
		EnableNetDevice(true, idx);
	}
	__finally
	{

	}

	PrintErrorMsg(argv[0], dwError);
	return dwError;
}


// TODO: GetDeviceList
DWORD
GetDeviceList(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	RPC_WSTR strGuid = NULL;

	vector<MIB_IF_ROW2>* wlan = getDevices(NdisPhysicalMediumNative802_11); //WLAN adapters
//see https://msdn.microsoft.com/en-us/library/windows/desktop/aa814491(v=vs.85).aspx, "PhysicalMediumType" for a full list
	for (auto &row : *wlan)
	{
		//do some additional filtering, this needs to be changed for non-WLAN
		if ((row.PhysicalMediumType == NdisPhysicalMediumNative802_11)) {
      if (row.InterfaceAndOperStatusFlags.FilterInterface == false) {
        //if (UuidToStringW(&row.InterfaceGuid, &strGuid) == RPC_S_OK) {
        if (UuidToStringW(&row.InterfaceGuid, &strGuid) == RPC_S_OK) {
          wcout << row.InterfaceIndex;
          wcout << L" , GUID: " << strGuid;
          wcout << L" , Desc: " << row.Description;
          wcout << L" , alias: " << row.Alias;
          wcout << endl;
				}
			}
		}
		/*
		if (row.TunnelType == TUNNEL_TYPE_NONE &&
			row.AccessType != NET_IF_ACCESS_LOOPBACK &&
			row.Type == IF_TYPE_IEEE80211 &&
			row.InterfaceAndOperStatusFlags.HardwareInterface == TRUE)
		{
			//HERE BE DRAGONS!
			//wcout << "  *";
		}*/
	}
	PrintErrorMsg(argv[0], dwError);
	return (dwError);
}

DWORD
GetInterfaceList(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	int if_type = 0;
	PMIB_IF_TABLE2 if_table = NULL;
	unsigned long size = 0;
	unsigned int i;
	RPC_WSTR strGuid = NULL;
	__try
	{
		if (argc != 1)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// Retrieve list of network interfaces
		//vista above only, only enabled NIC
		//wcout << "GetIfTable2" << endl;
		if (GetIfTable2(&if_table) == NOERROR && if_table) {
			//wcout << "Num: "<< if_table->NumEntries << endl;
			for (i = 0; i < if_table->NumEntries; i++) {
				if ((if_table->Table[i].Type == IF_TYPE_ETHERNET_CSMACD) || (if_table->Table[i].Type == IF_TYPE_IEEE80211)) {
					if (if_table->Table[i].InterfaceAndOperStatusFlags.HardwareInterface 
						&& (if_table->Table[i].OperStatus != 6)
						//&& if_table->Table[i].InterfaceAndOperStatusFlags.ConnectorPresent
						)
					{
						if (if_table->Table[i].Type == IF_TYPE_ETHERNET_CSMACD)
							wcout << L"LAN  ";
						if (if_table->Table[i].Type == IF_TYPE_IEEE80211)
							wcout << L"WLAN ";
						//ConnectorPresent : physical network adapter.
						wcout << L": " << if_table->Table[i].InterfaceIndex;
						if (UuidToStringW(&if_table->Table[i].InterfaceGuid, &strGuid) == RPC_S_OK)
						{
							//GUID
							wcout << L" : " << (LPWSTR)strGuid;
							RpcStringFreeW(&strGuid);
						}
						wcout << L" : " << if_table->Table[i].Description ;
						wcout << L" : " << if_table->Table[i].Alias ;
						//AdminStatus= 1 : interface is up, 2 : disable, 3 : testing mode
						wcout << L" : " << if_table->Table[i].AdminStatus;
						//show device exist or not/ disable will be 0
						//wcout << L" : " << if_table->Table[i].InterfaceAndOperStatusFlags.ConnectorPresent;
						//wcout << L" : " << if_table->Table[i].OperStatus;
						//wcout << "\t = HW ";
						//if (if_table->Table[i].OperStatus == IfOperStatusUp) {
							//The interface is up and able to pass packets
						//	wcout << " UP";
						//}
						wcout << endl;
					}
				}
			}
		}	
	}
	__finally
	{
		// clean up
		if (if_table)
			FreeMibTable(if_table);
	}
	PrintErrorMsg(argv[0], dwError);
	return (dwError);
}

/*
//get network interface name

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

DWORD
GetInterfaceName(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
) 
{
	DWORD dwError = ERROR_SUCCESS;
	// Declare and initialize variables
	PIP_INTERFACE_INFO pInfo = NULL;
	ULONG ulOutBufLen = 0;

	int i;
	__try
	{
		if (argc != 1)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// Make an initial call to GetInterfaceInfo to get
		// the necessary size in the ulOutBufLen variable
		dwError = GetInterfaceInfo(NULL, &ulOutBufLen);
		if (dwError == ERROR_INSUFFICIENT_BUFFER) {
			pInfo = (IP_INTERFACE_INFO *)MALLOC(ulOutBufLen);
			if (pInfo == NULL) {
				wcerr << "Unable to allocate memory needed to call GetInterfaceInfo\n" << endl;
				__leave;
			}
		}
		// Make a second call to GetInterfaceInfo to get
		// the actual data we need
		dwError = GetInterfaceInfo(pInfo, &ulOutBufLen);
		if (dwError == NO_ERROR) {
			wcout << "Number of Adapters: " <<  pInfo->NumAdapters <<endl;
			for (i = 0; i < pInfo->NumAdapters; i++) {
				wcout << "Adapter [" << i << "]: " << pInfo->Adapter[i].Index ;
				wcout << " : " << pInfo->Adapter[i].Name << endl;
			}
		}
		else if (dwError == ERROR_NO_DATA) {
			wcerr << "There are no network adapters with IPv4 enabled on the local system" << endl;
		}
		else {
			wcerr << "GetInterfaceInfo failed with error: %d" << dwError << endl;
			LPVOID lpMsgBuf;

			if (FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dwError,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
				(LPTSTR)&lpMsgBuf,
				0,
				NULL)) {
				wcerr << "\tError: " << lpMsgBuf <<endl;
			}
			LocalFree(lpMsgBuf);
		}
	}
	__finally
	{
		// clean up
		FREE(pInfo);
	}
	PrintErrorMsg(argv[0], dwError);
	return (dwError);
}
*/
// get interface capability and supported auth/cipher
DWORD
GetInterfaceCapability(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    PWLAN_INTERFACE_CAPABILITY pCapability = NULL;
    PWLAN_AUTH_CIPHER_PAIR_LIST pSupportedAuthCipherList = NULL;
    DWORD dwDataSize;
    UINT i;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        
        if (( dwError = WlanGetInterfaceCapability(
                            hClient, 
                            &guidIntf, 
                            NULL,               // reserved
                            &pCapability
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // print interface capability information
        if (pCapability->interfaceType == wlan_interface_type_emulated_802_11)
        {
            wcout << L"Emulated 802.11 NIC." << endl;
        }
        else if (pCapability->interfaceType == wlan_interface_type_native_802_11)
        {
            wcout << L"Native 802.11 NIC." << endl;
        }
        else
        {
            wcout << L"Unknown NIC." << endl;
        }
        
        // print supported PHY type
        wcout << L"Supports " << pCapability->dwNumberOfSupportedPhys << L" PHY types:" << endl;
        for (i = 0; i < pCapability->dwNumberOfSupportedPhys; i++)
        {
            wcout << L"\t" << GetPhyTypeString(pCapability->dot11PhyTypes[i]) << endl;
        }

        // query supported auth/cipher for infrastructure
        if ((dwError = WlanQueryInterface(
                        hClient,
                        &guidIntf,
                        wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
                        NULL,                   // reserved
                        &dwDataSize,
                        (PVOID *)&(pSupportedAuthCipherList),
                        NULL                    // not interesed in the type of the opcode value
                        )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // print auth/cipher algorithms
        wcout << L"Supported auth cipher pairs (infrastructure):" << endl;
        for (i = 0; i < pSupportedAuthCipherList->dwNumberOfItems; i++)
        {
            wcout << L"\t"; 
            wcout << GetAuthAlgoString(pSupportedAuthCipherList->pAuthCipherPairList[i].AuthAlgoId);
            wcout << L" and ";
            wcout << GetCipherAlgoString(pSupportedAuthCipherList->pAuthCipherPairList[i].CipherAlgoId) << endl;
        }

        WlanFreeMemory(pSupportedAuthCipherList);
        pSupportedAuthCipherList = NULL;

        // query supported auth/cipher for ad hoc
        if ((dwError = WlanQueryInterface(
                        hClient,
                        &guidIntf,
                        wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,
                        NULL,                   // reserved
                        &dwDataSize,
                        (PVOID *)&(pSupportedAuthCipherList),
                        NULL                    // not interesed in the type of the opcode value
                        )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // print auth/cipher algorithms
        wcout << L"Supported auth cipher pairs (ad hoc):" << endl;
        for (i = 0; i < pSupportedAuthCipherList->dwNumberOfItems; i++)
        {
            wcout << L"\t"; 
            wcout << GetAuthAlgoString(pSupportedAuthCipherList->pAuthCipherPairList[i].AuthAlgoId);
            wcout << L" and ";
            wcout << GetCipherAlgoString(pSupportedAuthCipherList->pAuthCipherPairList[i].CipherAlgoId) << endl;
        }

        WlanFreeMemory(pSupportedAuthCipherList);
        pSupportedAuthCipherList = NULL;
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

	PrintErrorMsg(argv[0], dwError);
	return dwError;
}

DWORD
GetInterfaceIndex(
    __in GUID guid
)
{
	DWORD dwError = -1;
	//GUID guidIntf;
	int if_type = 0;
	PMIB_IF_TABLE2 if_table = NULL;
	unsigned long size = 0;
	unsigned int i;
	RPC_WSTR strGuid = NULL;
	
	__try
	{
		// Retrieve list of network interfaces
		//vista above only, only enabled NIC
		if (GetIfTable2(&if_table) == NOERROR && if_table) {
			for (i = 0; i < if_table->NumEntries; i++) {
				if ((if_table->Table[i].Type == IF_TYPE_ETHERNET_CSMACD) || (if_table->Table[i].Type == IF_TYPE_IEEE80211)) {
					if (if_table->Table[i].InterfaceAndOperStatusFlags.HardwareInterface 
						&& (if_table->Table[i].OperStatus != 6)
						)
					{
						if (if_table->Table[i].InterfaceGuid == guid)
						{
                //wcout << L"interface index: " << if_table->Table[i].InterfaceIndex << endl;
                dwError = if_table->Table[i].InterfaceIndex;
                break;
						}
					}
				}
			}
		}
	}
	__finally
	{
		// clean up
		if (if_table)
			FreeMibTable(if_table);
	}
	return (dwError);
}
// query interface connection state
DWORD
State(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hClient = NULL;
	GUID guidIntf;
	WLAN_INTERFACE_STATE isState;
	PWLAN_CONNECTION_ATTRIBUTES pCurrentNetwork = NULL;
	WCHAR strSsid[DOT11_SSID_MAX_LENGTH + 1];
	//WLAN_RADIO_STATE wlanRadioState;
	PVOID pData = NULL;
	DWORD dwDataSize = 0;
	//UINT i;

	__try
	{
		if (argc != 2)
		{
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}

		// get the interface GUID
		if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
		{
			wcerr << L"Invalid GUID " << argv[1] << endl;
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}

		// open handle
		if ((dwError = OpenHandleAndCheckVersion(
			&hClient
		)) != ERROR_SUCCESS)
		{
			__leave;
		}

		// query interface state
		if ((dwError = WlanQueryInterface(
			hClient,
			&guidIntf,
			wlan_intf_opcode_interface_state,
			NULL,                       // reserved
			&dwDataSize,
			&pData,
			NULL                        // not interesed in the type of the opcode value
		)) != ERROR_SUCCESS)
		{
			__leave;
		}

		if (dwDataSize != sizeof(WLAN_INTERFACE_STATE))
		{
			dwError = ERROR_INVALID_DATA;
			__leave;
		}

		isState = *((PWLAN_INTERFACE_STATE)pData);

		// print interface state
		wcout << L"Interface state: " << GetInterfaceStateString(isState) << L"." << endl;

		WlanFreeMemory(pData);
		pData = NULL;

		// query the current connection
		if ((dwError = WlanQueryInterface(
			hClient,
			&guidIntf,
			wlan_intf_opcode_current_connection,
			NULL,                       // reserved
			&dwDataSize,
			&pData,
			NULL                        // not interesed in the type of the opcode value
		)) == ERROR_SUCCESS &&
			dwDataSize == sizeof(WLAN_CONNECTION_ATTRIBUTES)
			)
		{
			pCurrentNetwork = (PWLAN_CONNECTION_ATTRIBUTES)pData;
		}

		// we don't treat ERROR_INVALID_STATE as an error for querying the interface
		if (dwError == ERROR_INVALID_STATE)
		{
			dwError = ERROR_SUCCESS;
		}

		if (pCurrentNetwork == NULL)
		{
			// no connection information
			__leave;
		}

		// print current connection information
		if (pCurrentNetwork->isState == wlan_interface_state_connected)
			wcout << L"\tCurrently connected to \"";
		else if (pCurrentNetwork->isState == wlan_interface_state_ad_hoc_network_formed)
			wcout << L"\tCurrently formed \"";
		else if (pCurrentNetwork->isState == wlan_interface_state_associating ||
			pCurrentNetwork->isState == wlan_interface_state_discovering ||
			pCurrentNetwork->isState == wlan_interface_state_authenticating
			)
			wcout << L"\tCurrently connecting to \"";

		wcout << SsidToStringW(strSsid, sizeof(strSsid) / sizeof(WCHAR), &pCurrentNetwork->wlanAssociationAttributes.dot11Ssid);
		wcout << L"\" using profile \"" << pCurrentNetwork->strProfileName << "\"" << endl;
		wcout << L"\tconnection mode: " << GetConnectionModeString(pCurrentNetwork->wlanConnectionMode) << endl;
		wcout << L"\tBSS type: " << GetBssTypeString(pCurrentNetwork->wlanAssociationAttributes.dot11BssType) << endl;
		if (pCurrentNetwork->isState == wlan_interface_state_connected) {
			wcout << L"\tBSSID: " << GetBssidString(pCurrentNetwork->wlanAssociationAttributes.dot11Bssid) << endl;
			wcout << L"\tPHY type: " << GetPhyTypeString(pCurrentNetwork->wlanAssociationAttributes.dot11PhyType) << endl;
			wcout << L"\tSignal: " << pCurrentNetwork->wlanAssociationAttributes.wlanSignalQuality << L" %" << endl;
			wcout << L"\tTx Rate: " << pCurrentNetwork->wlanAssociationAttributes.ulTxRate << endl;
			wcout << L"\tRx Rate: " << pCurrentNetwork->wlanAssociationAttributes.ulRxRate << endl;
		}
	}
	__finally
	{
		if (pData != NULL)
		{
			WlanFreeMemory(pData);
		}

		// clean up
		if (hClient != NULL)
		{
			WlanCloseHandle(
				hClient,
				NULL            // reserved
			);
		}
	}

	PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// set the radio state
DWORD
SetRadioState(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    PWLAN_INTERFACE_CAPABILITY pInterfaceCapability = NULL;
    DWORD i;
    WLAN_PHY_RADIO_STATE wlanPhyRadioState;

    __try
    {
        if (argc != 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        if (_wcsicmp(argv[2], L"on") == 0)
        {
            wlanPhyRadioState.dot11SoftwareRadioState = dot11_radio_state_on;
        }
        else if (_wcsicmp(argv[2], L"off") == 0)
        {
            wlanPhyRadioState.dot11SoftwareRadioState = dot11_radio_state_off;
        }
        else
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }
        
        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // get interface capability, which includes the supported PHYs
        if ((dwError = WlanGetInterfaceCapability(
                    hClient,
                    &guidIntf,
                    NULL,                       // reserved
                    &pInterfaceCapability
                    )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // set radio state on every PHY
        for (i = 0; i < pInterfaceCapability->dwNumberOfSupportedPhys; i++)
        {
            // set radio state on every PHY
            wlanPhyRadioState.dwPhyIndex = i;

            if ((dwError = WlanSetInterface(
                            hClient, 
                            &guidIntf, 
                            wlan_intf_opcode_radio_state, 
                            sizeof(wlanPhyRadioState),
                            (PBYTE)&wlanPhyRadioState,
                            NULL                        // reserved
                            )) != ERROR_SUCCESS)
            {
                // rollback is nice to have, but not required
                __leave;
            }
        }

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }

        if (pInterfaceCapability != NULL)
        {
            WlanFreeMemory(pInterfaceCapability);
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// query basic interface information
DWORD
QueryInterface(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    WLAN_INTERFACE_STATE isState;
    PWLAN_CONNECTION_ATTRIBUTES pCurrentNetwork = NULL;
    WCHAR strSsid[DOT11_SSID_MAX_LENGTH+1];
    WLAN_RADIO_STATE wlanRadioState;
    PVOID pData = NULL;
    DWORD dwDataSize = 0;
    UINT i;
    
    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // query radio state information
        // this opcode is not supported in XP
        if ((dwError = WlanQueryInterface(
                        hClient,
                        &guidIntf,
                        wlan_intf_opcode_radio_state,
                        NULL,                       // reserved
                        &dwDataSize,
                        &pData,
                        NULL                        // not interesed in the type of the opcode value
                        )) != ERROR_SUCCESS && 
                        dwError != ERROR_NOT_SUPPORTED)
        {
            __leave;
        }

        if (dwError == ERROR_SUCCESS)
        {
            if (dwDataSize != sizeof(WLAN_RADIO_STATE))
            {
                dwError = ERROR_INVALID_DATA;
                __leave;
            }
            
            wlanRadioState = *((PWLAN_RADIO_STATE)pData);

            // print radio state
            for (i = 0; i < wlanRadioState.dwNumberOfPhys; i++)
            {
                wcout << L"PHY " << wlanRadioState.PhyRadioState[i].dwPhyIndex << L": " << endl;
                wcout << L"\tSoftware radio state is " << GetRadioStateString(wlanRadioState.PhyRadioState[i].dot11SoftwareRadioState) << L"." << endl;
                wcout << L"\tHardware radio state is " << GetRadioStateString(wlanRadioState.PhyRadioState[i].dot11HardwareRadioState) << L"." << endl;
            }

            WlanFreeMemory(pData);
            pData = NULL;
        }
        else
        {
            // not supported in XP
            // print message
            wcout << L"Querying radio state is not supported." << endl;
        }

        // query interface state
        if ((dwError = WlanQueryInterface(
                        hClient,
                        &guidIntf,
                        wlan_intf_opcode_interface_state,
                        NULL,                       // reserved
                        &dwDataSize,
                        &pData,
                        NULL                        // not interesed in the type of the opcode value
                        )) != ERROR_SUCCESS)
        {
            __leave;
        }

        if (dwDataSize != sizeof(WLAN_INTERFACE_STATE))
        {
            dwError = ERROR_INVALID_DATA;
            __leave;
        }
        
        isState = *((PWLAN_INTERFACE_STATE)pData);
        
        // print interface state
        wcout << L"Interface state: " << GetInterfaceStateString(isState) << L"." << endl;

        WlanFreeMemory(pData);
        pData = NULL;

        // query the current connection
        if ((dwError = WlanQueryInterface(
                        hClient,
                        &guidIntf,
                        wlan_intf_opcode_current_connection,
                        NULL,                       // reserved
                        &dwDataSize,
                        &pData,
                        NULL                        // not interesed in the type of the opcode value
                        )) == ERROR_SUCCESS && 
              dwDataSize == sizeof(WLAN_CONNECTION_ATTRIBUTES)
            )
        {
            pCurrentNetwork = (PWLAN_CONNECTION_ATTRIBUTES)pData;
        }

        // we don't treat ERROR_INVALID_STATE as an error for querying the interface
        if (dwError == ERROR_INVALID_STATE)
        {
            dwError = ERROR_SUCCESS;
        }
        
        if (pCurrentNetwork == NULL)
        {
            // no connection information
            __leave;
        }
        
        // print current connection information
        if (pCurrentNetwork->isState == wlan_interface_state_connected)
            wcout << L"Currently connected to ";
        else if (pCurrentNetwork->isState == wlan_interface_state_ad_hoc_network_formed)
            wcout << L"Currently formed ";
        else if (pCurrentNetwork->isState == wlan_interface_state_associating ||
                 pCurrentNetwork->isState == wlan_interface_state_discovering ||   
                 pCurrentNetwork->isState == wlan_interface_state_authenticating
                 )
            wcout << L"Currently connecting to ";
        
        wcout << SsidToStringW(strSsid, sizeof(strSsid)/sizeof(WCHAR), &pCurrentNetwork->wlanAssociationAttributes.dot11Ssid);
        wcout << L" using profile " << pCurrentNetwork->strProfileName;
        wcout << L", connection mode is " << GetConnectionModeString(pCurrentNetwork->wlanConnectionMode);
        wcout << L", BSS type is " << GetBssTypeString(pCurrentNetwork->wlanAssociationAttributes.dot11BssType) << L"." << endl;

        wcout << L"Current PHY type: ";
        wcout << GetPhyTypeString(pCurrentNetwork->wlanAssociationAttributes.dot11PhyType) << endl;

    }
    __finally
    {
        if (pData != NULL)
        {
            WlanFreeMemory(pData);
        }
        
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// scan
DWORD
Scan(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // scan
        dwError = WlanScan(
                    hClient, 
                    &guidIntf, 
                    NULL,                   // don't perform additional probe for a specific SSID
                    NULL,                   // no IE data for the additional probe
                    NULL                    // reserved
                    );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// get the list of visible wireless networks
DWORD
GetVisibleNetworkList(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    PWLAN_AVAILABLE_NETWORK_LIST pVList = NULL;
    UINT i;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        if ((dwError = WlanGetAvailableNetworkList(
                            hClient,
                            &guidIntf,
                            0,                      // only show visible networks
                            NULL,                   // reserved
                            &pVList
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        // print all visible networks
        wcout << L"Total " << pVList->dwNumberOfItems << L" networks are visible." << endl;
        for (i = 0; i < pVList->dwNumberOfItems; i++)
        {
            wcout << L"Network " <<i << L":" << endl;
            PrintNetworkInfo(&pVList->Network[i]);
            wcout << endl;
        }

        WlanFreeMemory(pVList);
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// get driver statistics
DWORD
GetDriverStatistics(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    PVOID pData = NULL;
    DWORD dwSize;
    PWLAN_STATISTICS pStatistics;
    UINT i;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        
        if ((dwError = WlanQueryInterface(
                            hClient,
                            &guidIntf,
                            wlan_intf_opcode_statistics,
                            NULL,                       // reserved
                            &dwSize,
                            &pData,
                            NULL                        // not interesed in the type of the opcode value
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }

        pStatistics = (PWLAN_STATISTICS)pData;
        // print statistics information
        wcout << L"Four way handshake failures: \t";
        PrintCounterValue(pStatistics->ullFourWayHandshakeFailures);

        wcout << L"TKIP Counter Measures invoked: \t";
        PrintCounterValue(pStatistics->ullTKIPCounterMeasuresInvoked);

        // frame statistics
        wcout << L"Unicast counters\n";
        wcout << L"\tTransmitted frame count: \t";
        PrintCounterValue(pStatistics->MacUcastCounters.ullTransmittedFrameCount);
        wcout << L"\tReceived frame count: \t";
        PrintCounterValue(pStatistics->MacUcastCounters.ullReceivedFrameCount);
        wcout << L"\tWEP excluded count: \t";
        PrintCounterValue(pStatistics->MacUcastCounters.ullWEPExcludedCount);

        // frame statistics
        wcout << L"Multicast counters\n";
        wcout << L"\tTransmitted frame count: \t";
        PrintCounterValue(pStatistics->MacMcastCounters.ullTransmittedFrameCount);
        wcout << L"\tReceived frame count: \t";
        PrintCounterValue(pStatistics->MacMcastCounters.ullReceivedFrameCount);
        wcout << L"\tWEP excluded count: \t";
        PrintCounterValue(pStatistics->MacMcastCounters.ullWEPExcludedCount);

        for (i = 0; i < pStatistics->dwNumberOfPhys; i++)
        {
            wcout << L"PHY " << i << endl;
            wcout << L"\tTransmitted frame count: \t";
            PrintCounterValue(pStatistics->PhyCounters[i].ullTransmittedFrameCount);
            wcout << L"\tMulticast transmitted frame count: \t";
            PrintCounterValue(pStatistics->PhyCounters[i].ullMulticastTransmittedFrameCount);
            wcout << L"\tReceived frame count: \t";
            PrintCounterValue(pStatistics->PhyCounters[i].ullReceivedFrameCount);
            wcout << L"\tMulticast received frame count: \t";
            PrintCounterValue(pStatistics->PhyCounters[i].ullMulticastReceivedFrameCount);
        }
        
        WlanFreeMemory(pData);
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// get BSS list
DWORD
GetBssList(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    DOT11_SSID dot11Ssid = {0};
    PDOT11_SSID pDot11Ssid = NULL;
    DOT11_BSS_TYPE dot11BssType = dot11_BSS_type_any;
    BOOL bSecurityEnabled = TRUE;
    PWLAN_BSS_LIST pWlanBssList = NULL;
    UINT i;

    __try
    {
        if (argc != 2 && argc != 5)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        if (argc == 5)
        {
            // get SSID
            if ((dwError = StringWToSsid(argv[2], &dot11Ssid)) != ERROR_SUCCESS)
            {
                __leave;
            }

            pDot11Ssid = &dot11Ssid;

            // get BSS type
            if (_wcsicmp(argv[3],L"adhoc") == 0 || _wcsicmp(argv[3], L"a") == 0)
                dot11BssType = dot11_BSS_type_independent;
            else if (_wcsicmp(argv[3], L"infrastructure") == 0 || _wcsicmp(argv[3], L"i") == 0)
                dot11BssType = dot11_BSS_type_infrastructure;
            else
            {
                dwError = ERROR_INVALID_PARAMETER;
                __leave;
            }

            // get whether security enabled or not
            if (_wcsicmp(argv[4], L"secure") == 0 || _wcsicmp(argv[4], L"s") == 0)
                bSecurityEnabled = TRUE;
            else if (_wcsicmp(argv[4], L"unsecure") == 0 || _wcsicmp(argv[4], L"u") == 0)
                bSecurityEnabled = FALSE;
            else
            {
                dwError = ERROR_INVALID_PARAMETER;
                __leave;
            }
        }
        
        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        if ((dwError = WlanGetNetworkBssList(
                            hClient,
                            &guidIntf,
                            pDot11Ssid,
                            dot11BssType,
                            bSecurityEnabled,
                            NULL,                       // reserved
                            &pWlanBssList
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
		//wcout << L"\tWlanBssList number: " << pWlanBssList->dwNumberOfItems << endl;
        for (i = 0; i < pWlanBssList->dwNumberOfItems; i++)
        {
            PrintBssInfo(&pWlanBssList->wlanBssEntries[i]);
        }
		wcout << L"(Total: " << pWlanBssList->dwNumberOfItems << L")";
        WlanFreeMemory(pWlanBssList);
    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

//https://msdn.microsoft.com/en-us/library/windows/desktop/ms706851(v=vs.85).aspx
// connect to a network using a saved profile
DWORD
Connect(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{

    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    DOT11_SSID dot11Ssid = {0};
    WLAN_CONNECTION_PARAMETERS wlanConnPara;
	/*
	if (argc == 6) {
		string macstring = CW2A(argv[5]);
	}*/
    __try
    {
        if (argc < 5)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get SSID
        if ((dwError = StringWToSsid(argv[2], &dot11Ssid)) != ERROR_SUCCESS)
        {
            __leave;
        }

        // set the connection mode (connecting using a profile)
        wlanConnPara.wlanConnectionMode = wlan_connection_mode_profile;
        // set the profile name
        wlanConnPara.strProfile = argv[4];
        // set the SSID
        wlanConnPara.pDot11Ssid = &dot11Ssid;

        // get BSS type
        if (_wcsicmp(argv[3],L"adhoc") == 0 || _wcsicmp(argv[3], L"a") == 0)
            wlanConnPara.dot11BssType = dot11_BSS_type_independent;
        else if (_wcsicmp(argv[3], L"infrastructure") == 0 || _wcsicmp(argv[3], L"i") == 0)
            wlanConnPara.dot11BssType = dot11_BSS_type_infrastructure;
        else
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }
		
		if (OSMajor >= 6) {
			
			if (argc == 6) {
				// DOT11_BSSID_LIST 
				DOT11_BSSID_LIST DesiredBssidList;

				//WLAN_BSS_LIST *bsslst;
				//WlanGetNetworkBssList(hClientHandle, &pIfInfo->InterfaceGuid, &pBssList->Network[j].dot11Ssid, pBssList->Network[j].dot11BssType, true, NULL, &bsslst);
				DesiredBssidList.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
				DesiredBssidList.Header.Revision = DOT11_BSSID_LIST_REVISION_1;
				DesiredBssidList.Header.Size = sizeof(DOT11_BSSID_LIST);
				DesiredBssidList.uNumOfEntries = 1; // If I change this to 0, it connects without a problem, but I can't control to which AP
				DesiredBssidList.uTotalNumOfEntries = 1;
				
				//unsigned char MAC[6];
				//vector<string> R; //cause VC C2712
				/*
				uint8_t R[6];
				
				
				
				//if ((dwError = StringWToBSSID(macstring, &R)) != ERROR_SUCCESS) {
				if ((dwError = StringWToBSSID(macstring, R)) != ERROR_SUCCESS) {
					dwError = ERROR_INVALID_PARAMETER;
					__leave;
				}
				//for (int i = 0; (i < 6) && (i < R.size()); ++i) {
				for (int i = 0; (i < 6); ++i) {
					//MAC[i] = (unsigned char)strtoul(R[i].c_str(), NULL, 16);
					//DesiredBssidList.BSSIDs[0][i] = (unsigned char)strtoul(R[i].c_str(), NULL, 16);
					DesiredBssidList.BSSIDs[0][i] = R[i];
				}
				printf("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
					DesiredBssidList.BSSIDs[0][0], DesiredBssidList.BSSIDs[0][1],
					DesiredBssidList.BSSIDs[0][2], DesiredBssidList.BSSIDs[0][3],
					DesiredBssidList.BSSIDs[0][3], DesiredBssidList.BSSIDs[0][5]);
					*/
				wlanConnPara.pDesiredBssidList = &DesiredBssidList;
			}
			else {
				wlanConnPara.pDesiredBssidList = NULL;
			}
			
		} else {
			// the desired BSSID list is empty (XP must NULL)
			wlanConnPara.pDesiredBssidList = NULL;
		}
        // no connection flags
        wlanConnPara.dwFlags = 0;

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        
        dwError = WlanConnect(
                    hClient,
                    &guidIntf,
                    &wlanConnPara,
                    NULL            // reserved
                    );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// discovery a network without using a saved profile
DWORD
Discover(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    DOT11_SSID dot11Ssid = {0};
    WLAN_CONNECTION_PARAMETERS wlanConnPara;

    __try
    {
        if (argc != 5)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get SSID
        if ((dwError = StringWToSsid(argv[2], &dot11Ssid)) != ERROR_SUCCESS)
        {
            __leave;
        }

        // profile is ignored for discovery
        wlanConnPara.strProfile = NULL;
        // set the SSID
        wlanConnPara.pDot11Ssid = &dot11Ssid;

        // get BSS type
        if (_wcsicmp(argv[3],L"adhoc") == 0 || _wcsicmp(argv[3], L"a") == 0)
            wlanConnPara.dot11BssType = dot11_BSS_type_independent;
        else if (_wcsicmp(argv[3], L"infrastructure") == 0 || _wcsicmp(argv[3], L"i") == 0)
            wlanConnPara.dot11BssType = dot11_BSS_type_infrastructure;
        else
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get whether security enabled or not
        if (_wcsicmp(argv[4], L"secure") == 0 || _wcsicmp(argv[4], L"s") == 0)
            wlanConnPara.wlanConnectionMode = wlan_connection_mode_discovery_secure;
        else if (_wcsicmp(argv[4], L"unsecure") == 0 || _wcsicmp(argv[4], L"u") == 0)
            wlanConnPara.wlanConnectionMode = wlan_connection_mode_discovery_unsecure;
        else
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // the desired BSSID list is empty
        wlanConnPara.pDesiredBssidList = NULL;
        // no connection flags
        wlanConnPara.dwFlags = 0;

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
    
        dwError = WlanConnect(
                    hClient,
                    &guidIntf,
                    &wlanConnPara,
                    NULL            // reserved
                    );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }

    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// disconnect from the current network
DWORD
Disconnect(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;

    __try
    {
        if (argc != 2)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        dwError = WlanDisconnect(
                        hClient, 
                        &guidIntf, 
                        NULL            // reserved
                        );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }
    
    PrintErrorMsg(argv[0], dwError);
	return dwError;
}

// save a temporary profile
// a temporary profile can be generated by the service for discovery
// or passed with WlanConnect when the connection mode is wlan_connection_mode_temporary_profile
DWORD
SaveTemporaryProfile(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwError = ERROR_SUCCESS;
    HANDLE hClient = NULL;
    GUID guidIntf;
    DWORD dwFlags = 0;

    __try
    {
        if (argc != 3)
        {
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // get the interface GUID
        if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
        {
            wcerr << L"Invalid GUID " << argv[1] << endl;
            dwError = ERROR_INVALID_PARAMETER;
            __leave;
        }

        // open handle
        if ((dwError = OpenHandleAndCheckVersion(
                            &hClient
                            )) != ERROR_SUCCESS)
        {
            __leave;
        }
        
        dwError = WlanSaveTemporaryProfile(
                        hClient, 
                        &guidIntf, 
                        argv[2],        // profile name
                        NULL,           // use default ACL
                        0,              // no profile flags 
                        TRUE,           // overwrite the existing profile
                        NULL            // reserved
                        );

    }
    __finally
    {
        // clean up
        if (hClient != NULL)
        {
            WlanCloseHandle(
                hClient, 
                NULL            // reserved
                );
        }
    }
    PrintErrorMsg(argv[0], dwError);
	return dwError;
}
// show version
DWORD
Version(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
) 
{
	wcout << VERSION << endl;
	return ERROR_SUCCESS;
}

//register
DWORD
GetReg(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
);
DWORD
SetReg(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
);
// show help messages
DWORD
Help(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
);

//typedef VOID (*WLSAMPLE_FUNCTION) (int argc, LPWSTR argv[]);
typedef DWORD (*WLAN_FUNCTION) (int argc, LPWSTR argv[]);

typedef struct _WLAN_COMMAND {
    LPWSTR strCommandName;           // command name
    LPWSTR strShortHand;             // a shorthand for the command
    WLAN_FUNCTION Func;         // pointer to the function
    LPWSTR strHelpMessage;          // help message
    LPWSTR strParameters;           // parameters for the command
    BOOL bRemarks;                  // whether have remarks for the command
    LPWSTR strRemarks;              // remarks
} WLAN_COMMAND, *PWLAN_COMMAND;

WLAN_COMMAND g_Commands[] = {
    // interface related commands
    {
        L"EnumInterface",
        L"ei",
        EnumInterface,
        L"Enumerate wireless interfaces and print the basic interface information.",
        L"",
        FALSE,
        L""
    },
	{
		L"GetDeviceList",
		L"gd",
		GetDeviceList,
		L"Enumerate ethernet and wireless interfaces and print the interface information.",
		L"",
		FALSE,
		L""
	},
	{
		L"GetInterfaceList",
		L"gi",
		GetInterfaceList,
		L"Enumerate ethernet and wireless interfaces and print the interface information.",
		L"",
		FALSE,
		L""
	},
    {
        L"GetInterfaceCapability",
        L"gic",
        GetInterfaceCapability,
        L"Get the capability of an interface.",
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"QueryInterface",
        L"qi",
        QueryInterface,
        L"Query the basic information of an interface.",
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"SetRadioState",
        L"srs",
        SetRadioState,
        L"Set the software radio state.",
        L"<interface GUID> <on|off>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"GetDriverStatistics",
        L"gds",
        GetDriverStatistics,
        L"Get driver statistics." ,
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    // scan related commands
    {
        L"Scan",
        L"scan",
        Scan,
        L"Scan for available wireless networks.",
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"GetBssList",
        L"gbs",
        GetBssList,
        L"Get the list of BSS." ,
        L"<interface GUID> [<SSID> <infrastructure(i)|adhoc(a)> <secure(s)|unsecure(u)>]",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"GetVisibleNetworkList",
        L"gvl",
        GetVisibleNetworkList,
        L"Get the list of visible wireless networks.",
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    // profile releated commands
	{
		L"CreateProfile",
		L"cp",
		CreateProfile,
		L"Create a profile by a SSID and security.",
		L"<interface GUID> <SSID> <OPEN|WEP|SHARED|WPAPSK|WPA2PSK> <WEP|TKIP|AES> <KEY>",
		TRUE,
		L"Use EnumInterface (ei) command to get the GUID of an interface."
	},
    {
        L"SetProfile",
        L"sp",
        SetProfile,
        L"Set a profile by a xml file.",
        L"<interface GUID> <profile XML file name>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"SaveTempProfile",
        L"stp",
        SaveTemporaryProfile,
        L"Save the temporary profile used for the current connection.",
        L"<interface GUID> <profile name>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"GetProfile",
        L"gp",
        GetProfile,
        L"Get the content of a saved profile.",
        L"<interface GUID> <profile name>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"DeleteProfile",
        L"dp",
        DeleteProfile,
        L"Delete a saved profile.",
        L"<interface GUID> <profile name>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
	{
		L"DeleteProfileList",
		L"dpl",
		DeleteProfileList,
		L"Delete all saved profiles.",
		L"<interface GUID>",
		TRUE,
		L"Use EnumInterface (ei) command to get the GUID of an interface."
	},
    {
        L"SetProfileList",
        L"spl",
        SetProfileList,
        L"Set the preference order of saved profiles. The list must contain all profiles.",
        L"<interface GUID> <profile name>+",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"GetProfileList",
        L"gpl",
        GetProfileList,
        L"Get the list of saved profiles, in the preference order." ,
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
/*
	//Disable/enable Interface
	{
		L"DisableInterface",
		L"di",
		DisableInterface,
		L"Disable network Interface. (require Administrator)",
		L"<interface Index> ",
		TRUE,
		L"Use GetInterfaceList (gi) command to get the Index of an interface."
	},
	{
		L"EnableInterface",
		L"eni",
		EnableInterface,
		L"Enable network Interface. (require Administrator)",
		L"<interface Index> ",
		TRUE,
		L"Use GetInterfaceList (gi) command to get the Index of an interface."
	},
*/
    // connection related commands
    {
        L"Connect",
        L"conn",
        Connect,
        L"Connect to a wireless network using a saved profile.",
        L"<interface GUID> <SSID> <infrastructure(i)|adhoc(a)> <profile name> <BSSID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"Disconnect",
        L"dc",
        Disconnect,
        L"Disconnect from the current network.",
        L"<interface GUID>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
    {
        L"Discover",
        L"disc",
        Discover,
        L"Connect to a network without a saved profile. The WLAN service will discover the settings for connection.",
        L"<interface GUID> <SSID> <infrastructure(i)|adhoc(a)> <secure(s)|unsecure(u)>",
        TRUE,
        L"Use EnumInterface (ei) command to get the GUID of an interface."
    },
	{
		L"State",
		L"st",
		State,
		L"Get current state of an interface.",
		L"<interface GUID>",
		TRUE,
		L"Use EnumInterface (ei) command to get the GUID of an interface."
	},
	//register command
  {
      L"GetRegkeyValue",
      L"gr",
      GetReg,
      L"Get interface reg key's value.",
      L"<interface GUID> regkey",
      TRUE,
      L"Use EnumInterface (ei) command to get the GUID of an interface."
  },
  {
      L"SetRegkeyValue",
      L"sr",
      SetReg,
      L"Set interface reg key with value.",
      L"<interface GUID> regkey value",
      TRUE,
      L"Use EnumInterface (ei) command to get the GUID of an interface."
  },

    // other commands
    {
        L"RegisterNotif",
        L"r",
        RegisterNotification,
        L"Register ACM and MSM notifications.",
        L"",
        FALSE,
        L""
    },
	{
		L"version",
		L"ver",
		Version,
		L"Print Version.",
		L"[<command>]",
		FALSE,
		L""
	},
    {
        L"help",
        L"?",
        Help,
        L"Print this help message.",
        L"[<command>]",
        FALSE,
        L""
    }
};

DWORD
GetReg(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	GUID guidIntf;
	LPCWSTR regkey;
	TCHAR regkeyValue[2] = {0};
  DWORD regkeyValueSize = sizeof(regkeyValue);
	LPWSTR regpat=0;
	DWORD idx;
  int rc=0;
  
  if (argc != 3)
  {
    dwError = ERROR_INVALID_PARAMETER;
    //__leave;
  } else {
    // get the interface GUID
    if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
    {
      wcerr << L"Invalid GUID " << argv[1] << endl;
      dwError = ERROR_INVALID_PARAMETER;
      //__leave;
    } else {
      // get reg key name
      regkey = argv[2];
      // get interface index
      idx = GetInterfaceIndex(guidIntf);
      //printf("%04d\n", idx); 
      wchar_t wcsbuf[5];
      swprintf(wcsbuf, 5, L"%04d", idx);
      //wcout << wcsbuf << endl;
      //concat reg path
      //regpath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0003";
      wstring mywstring(REG_NIC_PATH);
      //wstring concatted_stdstr = mywstring + L"0003";
      wstring concatted_stdstr = mywstring + wcsbuf;
      LPCWSTR concatted = concatted_stdstr.c_str();
      rc = GetKeyData(HKEY_LOCAL_MACHINE, concatted, regkey, (LPBYTE)regkeyValue, regkeyValueSize);
      if (rc == 1) {
        //PrintErrorMsg(regkeyValue, dwError);
        wcout << regkeyValue << endl;
      } else {
        dwError = rc;
      }
    }
  }
	PrintErrorMsg(argv[0], dwError);
	return dwError;
}

DWORD
SetReg(
	__in int argc,
	__in_ecount(argc) LPWSTR argv[]
)
{
	DWORD dwError = ERROR_SUCCESS;
	GUID guidIntf;
	LPCWSTR regkey;
	LPCWSTR regkeyValue;
	LPWSTR regpat=0;
	DWORD idx;
  int rc=0;
  
  if (argc != 4)
  {
    dwError = ERROR_INVALID_PARAMETER;
    //__leave;
  } else {
    // get the interface GUID
    if (UuidFromString((RPC_WSTR)argv[1], &guidIntf) != RPC_S_OK)
    {
      wcerr << L"Invalid GUID " << argv[1] << endl;
      dwError = ERROR_INVALID_PARAMETER;
      //__leave;
    } else {
      // get reg key name
      regkey = argv[2];
      regkeyValue = argv[3];
      size_t regkeyValueSize = wcslen(regkeyValue);
      // get interface index
      idx = GetInterfaceIndex(guidIntf);
      wchar_t wcsbuf[5];
      swprintf(wcsbuf, 5, L"%04d", idx);
      //concat reg path
      //regpath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0003";
      wstring mywstring(REG_NIC_PATH);
      //wstring concatted_stdstr = mywstring + L"0003";
      wstring concatted_stdstr = mywstring + wcsbuf;
      LPCWSTR concatted = concatted_stdstr.c_str();
      //TODO: different reg key type
      rc = SetKeyData(HKEY_LOCAL_MACHINE, concatted, REG_SZ , regkey, (LPBYTE)regkeyValue, (DWORD)regkeyValueSize);
      if (rc == 1) {
        wcout << regkeyValue << endl;
      }else {
        dwError = rc;
      }
    }
  }
	PrintErrorMsg(argv[0], dwError);
	return dwError;
}
// show help messages
DWORD
Help(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    UINT i;

    if (argc == 1)
    {
        // show all commands
        wcout << L"wlan " << VERSION << endl;
		wcout << L" The following commands are available." << endl;
		wcout << L" Use \"help xyz\" to show the description of command xyz." << endl;
        for (i=0; i < sizeof(g_Commands)/sizeof(WLAN_COMMAND); i++)
        {
                wcout << L"\t"<< g_Commands[i].strCommandName;
                wcout << L"(" << g_Commands[i].strShortHand << L")" << endl;
        }
    }
    else if (argc == 2)
    {
        // show the description of a command
        for (i=0; i < sizeof(g_Commands)/sizeof(WLAN_COMMAND); i++)
        {
            if (_wcsicmp(argv[1], g_Commands[i].strCommandName) == 0 ||
                    _wcsicmp(argv[1], g_Commands[i].strShortHand) == 0)
            {
                wcout << L"Command: " << g_Commands[i].strCommandName;
                wcout << L"(" << g_Commands[i].strShortHand << L")" << endl;
                wcout << L"Description: " << g_Commands[i].strHelpMessage << endl;
                wcout << L"Usage: " << g_Commands[i].strCommandName;
                wcout << L"(" << g_Commands[i].strShortHand << L") ";
                wcout << g_Commands[i].strParameters << endl;
                if (g_Commands[i].bRemarks)
                {
                    wcout << L"Remarks: " << g_Commands[i].strRemarks << endl;
                }
                break;
            }
        }
    }
    else
    {
        PrintErrorMsg(argv[0], ERROR_INVALID_PARAMETER);
    }
	return ERROR_SUCCESS;
}

// command is stored in the global variable
DWORD
ExecuteCommand(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    UINT i = 0;

    for (i=0; i < sizeof(g_Commands)/sizeof(WLAN_COMMAND); i++)
    {
        // find the command and call the function
        if (_wcsicmp(argv[0], g_Commands[i].strCommandName) == 0 ||
            _wcsicmp(argv[0], g_Commands[i].strShortHand) == 0)
        {
			return g_Commands[i].Func(argc, argv);
            break;
        }
    }

    if (i == sizeof(g_Commands)/sizeof(WLAN_COMMAND))
    {
        wcerr << L"Invalid command " << argv[0] << L"!" << endl;
		return ERROR_INVALID_PARAMETER;
    }
	return -1;
}

// the main program

int _cdecl 
wmain(
    __in int argc, 
    __in_ecount(argc) LPWSTR argv[]
)
{
    DWORD dwRetCode = ERROR_SUCCESS;
	OSVERSIONINFOEX os;
	if (GetVersion2(&os) == TRUE) {
		//wcout << L"os major ver: " << os.dwMajorVersion << endl;
		OSMajor = os.dwMajorVersion;
	}
    if (argc <= 1)
    {
        wcout << L"Please type \"" << argv[0] << L" ?\" for help." << endl;
        dwRetCode = ERROR_INVALID_PARAMETER;
    }
    else
    {
        // don't pass in the first parameter
		dwRetCode = ExecuteCommand(argc-1, argv+1);
    }
	//wcout << "dwRetCode:" << dwRetCode;
    return dwRetCode;
}

