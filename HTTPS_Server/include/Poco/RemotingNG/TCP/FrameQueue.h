//
// FrameQueue.h
//
// $Id: //poco/1.7/RemotingNG/TCP/include/Poco/RemotingNG/TCP/FrameQueue.h#1 $
//
// Library: RemotingNG/TCP
// Package: TCP
// Module:  FrameQueue
//
// Definition of the FrameQueue class.
//
// Copyright (c) 2006-2012, Applied Informatics Software Engineering GmbH.
// All rights reserved.
//
// License: Applied Informatics Software and Source Code License Agreement
//


#ifndef RemotingNG_TCP_FrameQueue_INCLUDED
#define RemotingNG_TCP_FrameQueue_INCLUDED


#include "Poco/RemotingNG/TCP/TCP.h"
#include "Poco/RemotingNG/TCP/FrameHandler.h"
#include "Poco/Timespan.h"
#include "Poco/Semaphore.h"
#include "Poco/Mutex.h"
#include <deque>


namespace Poco {
namespace RemotingNG {
namespace TCP {


class RemotingNGTCP_API FrameQueue: public FrameHandler
	/// A queue of frames.
{
public:
	typedef Poco::AutoPtr<FrameQueue> Ptr;

	FrameQueue(Connection::Ptr pConnection, Poco::UInt32 frameType, Poco::UInt32 channel);
		/// Creates the FrameQueue, accepting frames having the
		/// given type and channel.
		
	~FrameQueue();
		/// Destroys the FrameQueue.

	Frame::Ptr dequeueFrame(Poco::Timespan timeout);
		/// If there is at least one frame in the queue, removes
		/// it from the queue and returns it.
		/// Otherwise waits until a frame arrives or the
		/// timeout expires.

	// FrameHandler
	bool handleFrame(Connection::Ptr pConnection, Frame::Ptr pFrame);

private:
	enum
	{
		MAX_QUEUE_SIZE = 256
	};
	
	typedef std::deque<Frame::Ptr> FrameDeque;
	
	Connection::Ptr _pConnection;
	Poco::UInt32 _frameType;
	Poco::UInt32 _channel;
	FrameDeque _queue;
	Poco::FastMutex _mutex;
	Poco::Semaphore _sema;
};


} } } // namespace Poco::RemotingNG::TCP


#endif // RemotingNG_TCP_FrameQueue_INCLUDED
