#pragma once
#include <xstring>			// std::wstring
/**
 Translate a Win32 Error into the matching string

 Use as a functor:

		DWORD dwErr = ::GetLastError();
		std::wstring szErr = CWin32ErrToString()(dwErr);
*/
class CWin32ErrToWString
{
public:
	// Override operator "()"
	std::wstring operator()(DWORD code)
	{
		// W32_ErrorTxt wraps the a common use of the API function FormatMessage() 
		
		PWSTR psz = 0;

		if (code == 0)
			code = ::GetLastError();

		DWORD dwLanguageId = MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT); 
		DWORD len = ::FormatMessage ( FORMAT_MESSAGE_FROM_SYSTEM 
									| FORMAT_MESSAGE_ALLOCATE_BUFFER
									, 0
									, code
									, dwLanguageId
									, (PWSTR)&psz 
									, 0, 0
									); 
		
		//	Appends \r\n to the error text, so remove these
		//	However its not documented - hence the asserts below
		if (len == 0)
		{	_ASSERTE(psz == 0 || L"unexpected!");
			psz = 0;	
		}
		else
		{	if (len > 1 && psz[--len] == L'\n')
				psz[len] = 0;
			else 
				_ASSERTE(!L"no newline!");
			
			if (len > 1 && psz[--len] == L'\r')
				psz[len] = 0;
			else 
				_ASSERTE(!L"no carriage return!");
		}
		std::wstring szRetVal(psz);
		::LocalFree(psz);
		return szRetVal;
	}
};
