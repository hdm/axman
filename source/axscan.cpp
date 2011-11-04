#include "objbase.h"
#include "objsafe.h"

#include <iostream>
#include <sstream>
#include <tchar.h>
#include <windows.h>

#include <atlbase.h>
#include <atlconv.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

/*
 
 This is mostly ripped from Shane Hird's axenum
 H D Moore <hdm [at] metasploit.com>
 
*/

/* 
The TypeLib info stuff has been ripped from Sean Baxter:
http://spec.winprog.org/typeinf2/
*/
DEFINE_GUID(IID_IDispatchEx, 0xA6EF9860, 0xC720, 0x11D0, 0x93, 0x37, 0x00, 0xA0, 0xC9, 0x0D, 0xCA, 0xA9);

CLSID clsid;
TCHAR clsid_str[MAX_PATH];
TCHAR outdir[MAX_PATH];
FILE *output;

/* Number of seconds to wait for enumeration */
#define MAX_ENUM_WAIT 10000

#define IMPLTYPE_MASK (IMPLTYPEFLAG_FDEFAULT | IMPLTYPEFLAG_FSOURCE | IMPLTYPEFLAG_FRESTRICTED)

std::string stringifyCustomType(HREFTYPE refType, ITypeInfo* pti) {
	ITypeInfo *pTypeInfo(pti);
	ITypeInfo *pCustTypeInfo;
	HRESULT hr(pTypeInfo->GetRefTypeInfo(refType, &pCustTypeInfo));
	if(hr) return "UnknownCustomType";
	BSTR bstrType;
	hr = pCustTypeInfo->GetDocumentation(-1, &bstrType, 0, 0, 0);
	if(hr) return "UnknownCustomType";
	char ansiType[MAX_PATH];
	WideCharToMultiByte(CP_ACP, 0, bstrType, -1, ansiType, MAX_PATH, 0, 0);
	if(bstrType) ::SysFreeString(bstrType);
	pCustTypeInfo->Release();
	return ansiType;
}

std::string stringifyTypeDesc(TYPEDESC* typeDesc, ITypeInfo* pTypeInfo) {
	std::ostringstream oss;
	if(typeDesc->vt == VT_PTR) {
		oss<< stringifyTypeDesc(typeDesc->lptdesc, pTypeInfo)<< '*';
		return oss.str();
	}
	if(typeDesc->vt == VT_SAFEARRAY) {
		oss<< "SAFEARRAY("
			<< stringifyTypeDesc(typeDesc->lptdesc, pTypeInfo)<< ')';
		return oss.str();
	}
	if(typeDesc->vt == VT_CARRAY) {
		oss<< stringifyTypeDesc(&typeDesc->lpadesc->tdescElem, pTypeInfo);
		for(int dim(0); typeDesc->lpadesc->cDims; ++dim) 
			oss<< '['<< typeDesc->lpadesc->rgbounds[dim].lLbound<< "..."
			<< (typeDesc->lpadesc->rgbounds[dim].cElements + 
			typeDesc->lpadesc->rgbounds[dim].lLbound - 1)<< ']';
		return oss.str();
	}
	if(typeDesc->vt == VT_USERDEFINED) {
		oss<< stringifyCustomType(typeDesc->hreftype, pTypeInfo);
		return oss.str();
	}

	switch(typeDesc->vt) {
		// VARIANT/VARIANTARG compatible types
	case VT_I2: return "short";
	case VT_I4: return "long";
	case VT_R4: return "float";
	case VT_R8: return "double";
	case VT_CY: return "CY";
	case VT_DATE: return "DATE";
	case VT_BSTR: return "BSTR";
	case VT_DISPATCH: return "IDispatch*";
	case VT_ERROR: return "SCODE";
	case VT_BOOL: return "VARIANT_BOOL";
	case VT_VARIANT: return "VARIANT";
	case VT_UNKNOWN: return "IUnknown*";
	case VT_UI1: return "BYTE";
	case VT_DECIMAL: return "DECIMAL";
	case VT_I1: return "char";
	case VT_UI2: return "USHORT";
	case VT_UI4: return "ULONG";
	case VT_I8: return "__int64";
	case VT_UI8: return "unsigned __int64";
	case VT_INT: return "int";
	case VT_UINT: return "UINT";
	case VT_HRESULT: return "HRESULT";
	case VT_VOID: return "void";
	case VT_LPSTR: return "char*";
	case VT_LPWSTR: return "wchar_t*";
	}
	return "BIG ERROR!";
}

int displayTypeInfo(IDispatch *dptr)
{
	ITypeInfo *pTypeInfo;
	HRESULT hr;
	USES_CONVERSION;

	hr = dptr->GetTypeInfo(0, 0, &pTypeInfo);
	if(hr) {
		fprintf(output, "ax[ax_name]['NoType'] = true;\n");
		return -1; 
	}

	TYPEATTR* typeAttr;
	pTypeInfo->GetTypeAttr(&typeAttr);

	BSTR interfaceName;
	hr = pTypeInfo->GetDocumentation(-1, &interfaceName, 0, 0, 0);
	if(interfaceName) ::SysFreeString(interfaceName);

	fprintf(output, "ax[ax_name]['FunctionCount'] = %d;\n", typeAttr->cFuncs);
	fprintf(output, "ax[ax_name]['Functions'] = new Array();\n");

	for(UINT curFunc(0); curFunc < typeAttr->cFuncs; ++curFunc) {
		FUNCDESC* funcDesc;
		hr = pTypeInfo->GetFuncDesc(curFunc, &funcDesc);
		fprintf(output, "ax[ax_name]['Functions'][%d] = new Array();\n", curFunc);

		//Skip restricted methods
		if (funcDesc->wFuncFlags & 1)
		{
		} else
		{
			BSTR methodName;
			hr |= pTypeInfo->GetDocumentation(funcDesc->memid, &methodName, 0, 0, 0);
			if(hr) { 
				pTypeInfo->ReleaseFuncDesc(funcDesc); 
				continue; 
			}

			_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Name'] = '%s';\n"), curFunc, OLE2T(methodName));
			_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Return'] = '%s';\n"), curFunc, stringifyTypeDesc(&funcDesc->elemdescFunc.tdesc,pTypeInfo).c_str());
			_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['ArgCount'] = %d;\n"), curFunc, funcDesc->cParams);			
			_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Args'] = new Array();\n"), curFunc);

			if(methodName) ::SysFreeString(methodName);
			for(UINT curParam(0); curParam < funcDesc->cParams; ++curParam) {
				_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Args'][%d] = '%s';\n"),curFunc, curParam, stringifyTypeDesc(&funcDesc->lprgelemdescParam[curParam].tdesc, pTypeInfo).c_str());
			}
			
			switch(funcDesc->invkind) {
			case INVOKE_PROPERTYGET: 
				_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Type'] = 'PropGet';\n"), curFunc);
				break;
			case INVOKE_PROPERTYPUT:
				_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Type'] = 'PropPut';\n"), curFunc);
				break;
			case INVOKE_PROPERTYPUTREF:
				_ftprintf(output, _T("ax[ax_name]['Functions'][%d]['Type'] = 'PropPutRef';\n"), curFunc);
				break;
			}

			bool invFlag = true;
			if (funcDesc->invkind == INVOKE_FUNC)
			{
				for (int j = 0; j < funcDesc->cParams; j++)
				{
					if (funcDesc->lprgelemdescParam[j].tdesc.vt != VT_BSTR && 
						funcDesc->lprgelemdescParam[j].tdesc.vt != VT_I4)
						invFlag = false;			
				}
			}
		}

		pTypeInfo->ReleaseFuncDesc(funcDesc);
	}

pTypeInfo->ReleaseTypeAttr(typeAttr);
pTypeInfo->Release();
return 0;
}


// 32-bit specific right now
void dbg_dump(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	_ftprintf(output, _T("// CRASH:%s CODE:0x%.8x ADDR=0x%.8x FLAGS=0x%.8x PARAMS=0x%.8x\n"), 
			clsid_str, 
			ExceptionInfo->ExceptionRecord->ExceptionCode,
			ExceptionInfo->ExceptionRecord->ExceptionAddress,
			ExceptionInfo->ExceptionRecord->ExceptionFlags,
			ExceptionInfo->ExceptionRecord->NumberParameters
			);

	_ftprintf(output, _T("// eax=%.8x ebx=%.8x ecx=%.8x\n// edx=%.8x esi=%.8x edi=%.8x\n// eip=%.8x esp=%.8x ebp=%.8x\n"), 
			clsid_str, 
			ExceptionInfo->ContextRecord->Eax,
			ExceptionInfo->ContextRecord->Ebx,
			ExceptionInfo->ContextRecord->Ecx,
			ExceptionInfo->ContextRecord->Edx,
			ExceptionInfo->ContextRecord->Esi,
			ExceptionInfo->ContextRecord->Edi,
			ExceptionInfo->ContextRecord->Eip,
			ExceptionInfo->ContextRecord->Esp,
			ExceptionInfo->ContextRecord->Ebp
			);
	_ftprintf(output, _T("ax[ax_name]['Fatal'] = true;\n"));
	_ftprintf(output, _T("ax[ax_name]['ExceptionCode'] = 0x%.8x;\n"), ExceptionInfo->ExceptionRecord->ExceptionCode);
	_ftprintf(output, _T("ax[ax_name]['ExceptionAddr'] = 0x%.8x;\n"), ExceptionInfo->ExceptionRecord->ExceptionAddress);
	_ftprintf(output, _T("\n"));

	fflush(output);
}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	dbg_dump(ExceptionInfo);
	ExitProcess(0);
}

void write_js_string(FILE *fd, BYTE *str) {
	BYTE *p;
	LONG i = 0;

	while (str[i] != 0) {
		if (str[i] == 0x27 || str[i] == 0x5C)
			fprintf(fd, "\\%c", str[i]);
		else
			fprintf(fd, "%c", str[i]);
		i++;
	}
}

int view_clsid(TCHAR* achKey) {
	HKEY hKeyQ;
	IObjectSafety *pOSafe = NULL;
	WCHAR clsidstring[MAX_PATH];
	DWORD cbData = MAX_PATH;
	TCHAR regkey[1024];
	BYTE rData[MAX_PATH]; 
	CHAR outname[MAX_PATH];
	DWORD tp;
	LONG retVal;
	
	// Class ID was passed in argv[1]
	_tcscpy_s(clsid_str, MAX_PATH, achKey);

	// Open the output file for this class
	sprintf(outname, "%s.js", achKey);

	output = fopen(outname, "w");
	if (! output)
		return(0);

	SetUnhandledExceptionFilter(bad_exception);

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, achKey, -1, clsidstring, MAX_PATH);
	CLSIDFromString(clsidstring, &clsid);
	
	_ftprintf(output, _T("var ax_name = '%s';\n"), clsid_str);
	fprintf(output, "ax[ax_name] = new Array();\n");

	// Obtain the description string
	sprintf(regkey, "Software\\Classes\\CLSID\\%s", achKey);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &hKeyQ );
	cbData = MAX_PATH;
	retVal = RegQueryValueEx(hKeyQ, NULL, NULL, &tp, rData, &cbData );
	RegCloseKey(hKeyQ);
	if (retVal == ERROR_SUCCESS) {	
		fprintf(output, "ax[ax_name]['Info'] = '");
		write_js_string(output, rData);
		fprintf(output, "';\n");	
	}

	// Obtain the program ID
	sprintf(regkey, "Software\\Classes\\CLSID\\%s\\ProgID", achKey);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &hKeyQ );
	cbData = MAX_PATH;
	retVal = RegQueryValueEx(hKeyQ, NULL, NULL, &tp, rData, &cbData );
	RegCloseKey(hKeyQ);
	if (retVal == ERROR_SUCCESS) {
		fprintf(output, "ax[ax_name]['ProgID'] = '");
		write_js_string(output, rData);
		fprintf(output, "';\n");	
	}
	
	// Obtain the program ID
	sprintf(regkey, "Software\\Classes\\CLSID\\%s\\InprocServer32", achKey);
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &hKeyQ );
	cbData = MAX_PATH;
	retVal = RegQueryValueEx(hKeyQ, NULL, NULL, &tp, rData, &cbData );
	RegCloseKey(hKeyQ);

	if (retVal == ERROR_SUCCESS) {
		fprintf(output, "ax[ax_name]['Server'] = '");
		write_js_string(output, rData);
		fprintf(output, "';\n");	
	}
	
	fflush(output);

	bool typedisplayed = false;
	

	HRESULT hr;
	hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IObjectSafety, (void**)&pOSafe);
	if (hr == S_OK) {
		DWORD dwSupported = 0;
		DWORD dwEnabled = 0;

		fflush(output);

		HRESULT hsd = pOSafe->SetInterfaceSafetyOptions(IID_IPersist, INTERFACESAFE_FOR_UNTRUSTED_DATA, INTERFACESAFE_FOR_UNTRUSTED_DATA);
		if (hsd == S_OK)
		{
			pOSafe->GetInterfaceSafetyOptions(IID_IPersist, &dwSupported, &dwEnabled);
			fprintf(output, "ax[ax_name]['SafeInit'] = new Array(%d, %d);\n", dwSupported, dwEnabled);
		}
		hsd = pOSafe->SetInterfaceSafetyOptions(IID_IDispatchEx, INTERFACESAFE_FOR_UNTRUSTED_CALLER, INTERFACESAFE_FOR_UNTRUSTED_CALLER);
		if (hsd == S_OK)
		{
			fprintf(output, "ax[ax_name]['SafeScript'] = new Array(%d, %d);\n", dwSupported, dwEnabled);
		}
		else {
			hsd = pOSafe->SetInterfaceSafetyOptions(IID_IDispatch, INTERFACESAFE_FOR_UNTRUSTED_CALLER, INTERFACESAFE_FOR_UNTRUSTED_CALLER);
			if (hsd == S_OK)
			{
				pOSafe->GetInterfaceSafetyOptions(IID_IDispatch, &dwSupported, &dwEnabled);
				fprintf(output, "ax[ax_name]['SafeScript'] = new Array(%d, %d);\n", dwSupported, dwEnabled);
			}
		}

		IDispatch *dptr = NULL;
		pOSafe->QueryInterface(IID_IDispatch, (void**)&dptr);
		if (hr == S_OK && dptr)
		{
			displayTypeInfo(dptr);
			dptr->Release();
		}
		typedisplayed = true;
		pOSafe->Release();
	}

	// Safe for scripting?
	sprintf(regkey, "Software\\Classes\\CLSID\\%s\\Implemented Categories\\{7DD95801-9882-11CF-9FA9-00AA006C42C4}", achKey);
	LONG retValScripting = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &hKeyQ );
	RegCloseKey(hKeyQ);
	
	// Safe for initialization?
	sprintf(regkey, "Software\\Classes\\CLSID\\%s\\Implemented Categories\\{7DD95802-9882-11CF-9FA9-00AA006C42C4}", achKey);
	LONG retValIniting = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &hKeyQ );
	RegCloseKey(hKeyQ);

	fflush(output);

	// Enumerate objects that are not safe for scripting/safe for initialization
	if (!typedisplayed)
	{
		fprintf(output, "ax[ax_name]['NotSafe'] = true;\n");
		IDispatch *dptr;
		hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IDispatch, (void**)&dptr);
		if (hr == S_OK)
		{
			displayTypeInfo(dptr);
			dptr->Release();
		} else {
			fprintf(output, "ax[ax_name]['IDispatchFailed'] = true;\n");
		}
	}		

	fclose(output);
	return(0);
}

int scan_clsid(TCHAR* achKey) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	TCHAR cmd[4096];
	TCHAR mod[MAX_PATH];
	HMODULE m;

	m = GetModuleHandle(NULL);

	GetModuleFileName(m, mod, MAX_PATH-1);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	_sntprintf_s(cmd, 4096, 4096-1, _T("%s GO %s"), mod, achKey);

	fflush(output);

	if(! CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		_ftprintf(output, _T("// SCAN ERROR: CreateProcess failed with 0x%.8x for %s\n"), GetLastError(), achKey); 
		return(-1);
	}

	/* Wait for the process to complete */
	if (WaitForSingleObject(pi.hProcess, MAX_ENUM_WAIT) == WAIT_TIMEOUT) {
		_ftprintf(output, _T("// SCAN ERROR: Timeout reached for %s\n"), achKey); 
		TerminateProcess(pi.hProcess, 0);
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	fflush(output);
	return(0);
}

int _tmain(int argc, _TCHAR* argv[])
{
	HKEY hKey;
	DWORD dwBufLen = MAX_PATH;
	DWORD cbName = MAX_PATH;
	TCHAR achKey[MAX_PATH];
	DWORD cSubKeys;
	FILETIME ftime;
	DWORD cbData = MAX_PATH;
	DWORD j = 0;

	if (argc <= 1) {
		fprintf(stderr, "Usage: axman [output-directory]\n");
		exit(0);
	}

	if (argc <= 2) {

		// Copy the output directory name
		_tcscpy_s(outdir, MAX_PATH, argv[1]);

		// Attempt to create it 
		CreateDirectory(outdir, NULL);

		// Attempt to enter it
		if (! SetCurrentDirectory(outdir)) {
			fprintf(stderr, "Error: could not create and enter the output directory\n");
			exit(0);
		}

		// Open the top-level objects.js
		output = fopen("objects.js", "w");

		/* Initialize the script arrays */
		fprintf(output, "var ax_objects = new Array(\n");
		fflush(output);

		RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Classes\\CLSID"), 0, KEY_READ, &hKey);
		RegQueryInfoKey(
			hKey, // key handle 
			NULL, // buffer for class name 
			NULL, // size of class string 
			NULL, // reserved 
			&cSubKeys, // number of subkeys 
			NULL, // longest subkey size 
			NULL, // longest class string 
			NULL, // number of values for this key 
			NULL, // longest value name 
			NULL, // longest value data 
			NULL, // security descriptor 
			NULL  // last write time 
		);

		for (j = 0; j<cSubKeys; j++)
		{
			cbName=MAX_PATH;
			achKey[0] = '\0';
			RegEnumKeyEx(hKey, j,
				achKey, 
				&cbName, 
				NULL, 
				NULL, 
				NULL, 
				&ftime); 
			_ftprintf(output, _T("\t'%s'%s\n"), achKey, j == (cSubKeys-1) ? _T("") : _T(","));
			fflush(output);
			scan_clsid(achKey);
		}
		fprintf(output, ");\n");
		fclose(output);
		RegCloseKey(hKey);
		return(0);
	}

	// Init OLE
	CoInitialize(NULL);

	// Call the enumerator
	view_clsid(argv[2]);

	// Free OLE
	CoUninitialize();
	return(0);
}
