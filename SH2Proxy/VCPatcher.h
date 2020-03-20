#ifndef VCPATCHER_H_
#define VCPATCHER_H_
#include "stdafx.h"

typedef struct D3DPRESENT_PARAMETERS {
	UINT                BackBufferWidth;
	UINT                BackBufferHeight;
	intptr_t*           BackBufferFormat;
	UINT                BackBufferCount;
	intptr_t* MultiSampleType;
	DWORD               MultiSampleQuality;
	intptr_t*       SwapEffect;
	HWND                hDeviceWindow;
	BOOL                Windowed;
	BOOL                EnableAutoDepthStencil;
	intptr_t*           AutoDepthStencilFormat;
	DWORD               Flags;
	UINT                FullScreen_RefreshRateInHz;
	UINT                PresentationInterval;
} D3DPRESENT_PARAMETERS, *LPD3DPRESENT_PARAMETERS;

class VCPatcher
{
public:
	bool Init();
};

#endif