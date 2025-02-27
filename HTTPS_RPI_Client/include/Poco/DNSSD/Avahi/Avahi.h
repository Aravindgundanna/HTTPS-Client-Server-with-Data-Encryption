//
// Avahi.h
//
// $Id: //poco/1.7/DNSSD/Avahi/include/Poco/DNSSD/Avahi/Avahi.h#1 $
//
// Library: DNSSD/Avahi
// Package: Implementation
// Module:  Avahi
//
// Basic definitions for the Poco DNSSD Avahi library.
// This file must be the first file included by every other DNSSD Avahi
// header file.
//
// Copyright (c) 2006-2011, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// This is unpublished proprietary source code of Applied Informatics.
// The contents of this file may not be disclosed to third parties, 
// copied or duplicated in any form, in whole or in part.
//


#ifndef DNSSD_Avahi_Avahi_INCLUDED
#define DNSSD_Avahi_Avahi_INCLUDED


#include "Poco/DNSSD/DNSSD.h"


//
// The following block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the Avahi_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// POCO_DNSSD_Avahi_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
//
#if defined(_WIN32) && defined(POCO_DLL)
	#if defined(Avahi_EXPORTS)
		#define POCO_DNSSD_Avahi_API __declspec(dllexport)
	#else
		#define POCO_DNSSD_Avahi_API __declspec(dllimport)
	#endif
#endif


#if !defined(POCO_DNSSD_Avahi_API)
	#define POCO_DNSSD_Avahi_API
#endif


#if defined(_MSC_VER)
	#if !defined(POCO_NO_AUTOMATIC_LIBS) && !defined(Avahi_EXPORTS)
		#pragma comment(lib, "PocoDNSSDAvahi" POCO_LIB_SUFFIX)
	#endif
#endif


namespace Poco {
namespace DNSSD {


void POCO_DNSSD_Avahi_API initializeDNSSD();
	/// Initialize the DNSSD subsystem.


void POCO_DNSSD_Avahi_API uninitializeDNSSD();
	/// Uninitialize the DNSSD subsystem.


} } // namespace Poco::DNSSD


#endif // DNSSD_Avahi_Avahi_INCLUDED
