//
// Domain.h
//
// $Id: //poco/1.7/DNSSD/include/Poco/DNSSD/Domain.h#1 $
//
// Library: DNSSD
// Package: Core
// Module:  Domain
//
// Definition of the Domain class.
//
// Copyright (c) 2006-2011, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// This is unpublished proprietary source code of Applied Informatics.
// The contents of this file may not be disclosed to third parties, 
// copied or duplicated in any form, in whole or in part.
//


#ifndef DNSSD_Domain_INCLUDED
#define DNSSD_Domain_INCLUDED


#include "Poco/DNSSD/DNSSD.h"


namespace Poco {
namespace DNSSD {


class POCO_DNSSD_API Domain
	/// Domain stores information about a browse domain.
{
public:
	Domain();
		/// Creates an empty Domain.

	Domain(Poco::Int32 networkInterface, const std::string& name, bool isDefault);
		/// Creates a Domain using the given information.
		///
		///    - networkInterface specifies the index of the interface the domain was discovered on.
		///    - name specifies the name of the domain.
		///    - isDefault specifies whether the domain is the default domain.

	~Domain();
		/// Destroys the Domain.

	Poco::Int32 networkInterface() const;
		/// Returns the index of the network interface the domain was discovered on.

	const std::string& name() const;
		/// Returns the name of the domain.

	bool isDefault() const;
		/// Returns true if the domain is the default domain.

private:
	Poco::Int32 _networkInterface;
	std::string _name;
	bool        _isDefault;
};


//
// inlines
//
inline Poco::Int32 Domain::networkInterface() const
{
	return _networkInterface;
}


inline const std::string& Domain::name() const
{
	return _name;
}


inline bool Domain::isDefault() const
{
	return _isDefault;
}


} } // namespace Poco::DNSSD


#endif // DNSSD_Domain_INCLUDED
