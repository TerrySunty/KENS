/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

#define mp(X, Y) std::make_pair(X, Y)
#define mt(X, Y, Z, W) std::make_tuple(X, Y, Z, W)

namespace E
{	

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::syscall_socket(UUID sysid, int pid, int domain, int protocol)
{
	int fd = this->createFileDescriptor(pid);
	auto data = new MyTCPContext;
	data->fd = fd;
	data->pid = pid;
	this->fd_to_context[mp(pid, fd)] = data;
	this->returnSystemCall(sysid, fd);
}

void TCPAssignment::close_cleanup(UUID sysid, int pid, int fd, MyTCPContext * mysock)
{
	//established, but no accepted
	//actually never happens
	if(mysock->fd == -1)
	{
		puts("established, but no accepted");
		auto welcsock = this->syn_ready[mp(mysock->ip, mysock->port)];
		welcsock->established.erase(welcsock->established.find(mysock));
		delete mysock;
		this->returnSystemCall(mysock->sysid, 0);
	}
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	if(this->fd_to_context[mp(pid, fd)]->isBound == true)
	{
		auto ip = this->fd_to_context[mp(pid, fd)]->ip;
		auto port = this->fd_to_context[mp(pid, fd)]->port;
		this->bound_set.erase(mp(ip, port));
		this->port_to_bound_ip[port].erase(ip);
		this->fd_to_context[mp(pid, fd)]->isBound = false;
	}
	for(auto it = this->srcdest_to_context.begin(); it!=this->srcdest_to_context.end(); it++)
	{
		if(it->second == this->fd_to_context[mp(pid, fd)])
		{
			this->srcdest_to_context.erase(it);
			break;
		}
	}
	for(auto it = this->syn_ready.begin(); it!=this->syn_ready.end(); it++)
	{
		if(it->second == this->fd_to_context[mp(pid, fd)])
		{
			this->syn_ready.erase(it);
			break;
		}
	}
	for(auto it=this->fd_to_context[mp(pid, fd)]->received.begin(); it!=this->fd_to_context[mp(pid, fd)]->received.end();it++) this->freePacket(*it);
	for(auto it=this->fd_to_context[mp(pid, fd)]->sent.begin(); it!=this->fd_to_context[mp(pid, fd)]->sent.end();it++) this->freePacket(*it);
	this->fd_to_context[mp(pid, fd)]->received.clear();
	this->fd_to_context[mp(pid, fd)]->sent.clear();
	this->fd_to_context[mp(pid, fd)]->connecting.clear();
	this->fd_to_context[mp(pid, fd)]->established.clear();
	delete this->fd_to_context[mp(pid, fd)];
	this->fd_to_context.erase(mp(pid, fd));
	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(sysid, 0);
}

void TCPAssignment::syscall_close(UUID sysid, int pid, int fd)
{
	bool sendFIN = false;
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	auto nowsock = this->fd_to_context[mp(pid, fd)];
	switch(nowsock->status)
	{
		case SYNSENT:
			nowsock->status = CLOSED;
			this->close_cleanup(sysid, pid, fd, nowsock);
			return;	
		case ESTAB:
		case SYNRCVD:
			nowsock->status = FIN_WAIT_1;
			nowsock->sysid = sysid;
			sendFIN = true;
			break;
		case CLOSE_WAIT:
			nowsock->status = LAST_ACK;
			nowsock->sysid = sysid;
			sendFIN = true;
			break;
		default:
			this->close_cleanup(sysid, pid, fd, nowsock);
			return;
	}
	if(sendFIN)
	{
		auto finpacket = this->allocatePacket(34 + 20);
		finpacket->writeData(14 + 12, &nowsock->ip, 4);
		finpacket->writeData(14 + 16, &nowsock->peerip, 4);
		nowsock->myack = nowsock->peerseq + 1;
		uint8_t tcp_seg[20];
		this->fillTCPHeader(tcp_seg, nowsock->port, nowsock->peerport,
								nowsock->myseq, nowsock->myack,
								false, false, true, 0);
		unsigned short chksum = ~NetworkUtil::tcp_sum(nowsock->ip, nowsock->peerip, tcp_seg, 20);
		*(unsigned short *)(tcp_seg + 16) = htons(chksum);
		finpacket->writeData(34, tcp_seg, 20);
		this->sendPacket("IPv4", finpacket);
		nowsock->myseq++;
	}
	
}

void TCPAssignment::syscall_bind(UUID sysid, int pid, int fd, struct sockaddr * addr, socklen_t len)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		//nonvalid fd
		this->returnSystemCall(sysid, -EBADF);
	}
	if(this->fd_to_context[mp(pid, fd)]->isBound == true)
	{
		//this socket is already bound
		this->returnSystemCall(sysid, -EINVAL);
	}
	auto data = this->fd_to_context[mp(pid, fd)];
	struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;
	auto ip_port = mp(in_addr->sin_addr.s_addr, in_addr->sin_port);
	if(ip_port.first == htonl(INADDR_ANY)
	&& (!this->port_to_bound_ip[ip_port.second].empty()))
	{
		// if requested addr is 0.0.0.0 and another concrete ip address(x.x.x.x) is already bound to requested port
		this->returnSystemCall(sysid, -EADDRINUSE);

	}
	if(this->bound_set.find(ip_port) != this->bound_set.end()
	|| this->bound_set.find(mp(htonl(INADDR_ANY), ip_port.second)) != this->bound_set.end())
	{
		// another socket is already bound to this addr
		this->returnSystemCall(sysid, -EADDRINUSE);
	}
	else
	{
		this->bound_set.insert(ip_port);
		this->port_to_bound_ip[ip_port.second].insert(ip_port.first);
		data->ip = ip_port.first;
		data->port = ip_port.second;
		data->isBound = true;
		this->returnSystemCall(sysid, 0);
	}
}

void TCPAssignment::syscall_getsockname(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(uuid, -EBADF);
	}
	auto data = this->fd_to_context[mp(pid, fd)];
	struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;

	*len = sizeof(struct sockaddr_in);
	in_addr->sin_family = AF_INET;
	in_addr->sin_port = data->port;
	in_addr->sin_addr.s_addr = data->ip;
	this->returnSystemCall(uuid, 0);

}

void TCPAssignment::syscall_getpeername(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(uuid, -EBADF);
	}
	auto data = this->fd_to_context[mp(pid, fd)];
	struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;

	*len = sizeof(struct sockaddr_in);
	in_addr->sin_family = AF_INET;
	in_addr->sin_port = data->peerport;
	in_addr->sin_addr.s_addr = data->peerip;
	this->returnSystemCall(uuid, 0);

}


void TCPAssignment::syscall_connect(UUID sysid, int pid, int fd, struct sockaddr * addr, socklen_t len)
{
	struct sockaddr_in * serv_addr = (struct sockaddr_in *)addr;
	auto servip = serv_addr->sin_addr.s_addr;
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	auto & nowsock = fd_to_context[mp(pid, fd)];
	if(nowsock->status == SYNSENT)
	{
		this->returnSystemCall(sysid, -EALREADY);
	}
	if(nowsock->status == ESTAB)
	{
		this->returnSystemCall(sysid, -EISCONN);
	}
	nowsock->myseq = random();
	//send SYN packet
	auto synpacket = this->allocatePacket(34+20);
	auto & srcip = nowsock->ip;
	if(nowsock->isBound == false)
	{
		int ifidx = this->getHost()->getRoutingTable((const uint8_t *)&servip);
		while(this->getHost()->getIPAddr((uint8_t *)&srcip, ifidx)==false);
		nowsock->isBound = true;
		do{
			nowsock->port = random() % 65536;
		} while(this->port_to_bound_ip[nowsock->port].find(srcip) != this->port_to_bound_ip[nowsock->port].end());
		this->port_to_bound_ip[nowsock->port].insert(srcip);
		this->bound_set.insert(mp(srcip, nowsock->port));
	}
	synpacket->writeData(14+12, &srcip, 4);
	synpacket->writeData(14+16, &servip, 4);
	uint8_t tcp_seg[20];
	this->fillTCPHeader(tcp_seg, nowsock->port, serv_addr->sin_port,
								nowsock->myseq, 0,
								true, false, false, 0);
	unsigned short chksum = ~NetworkUtil::tcp_sum(srcip, servip, tcp_seg, 20);
	*(unsigned short *)(tcp_seg + 16) = htons(chksum);
	synpacket->writeData(34, tcp_seg, 20);
	nowsock->sysid = sysid;
	nowsock->status = SYNSENT;
	nowsock->peerip = servip;
	nowsock->peerport = serv_addr->sin_port;
	this->srcdest_to_context[mt(nowsock->ip, nowsock->port, servip, serv_addr->sin_port)] = nowsock;
	this->syn_ready[mp(nowsock->ip, nowsock->port)] = nowsock;
	this->sendPacket("IPv4", synpacket);
	nowsock->myseq++;
}

void TCPAssignment::syscall_listen(UUID sysid, int pid, int fd, int backlog)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	auto nowsock = this->fd_to_context[mp(pid, fd)];
	if(this->syn_ready.find(mp(nowsock->ip, nowsock->port)) != this->syn_ready.end()
	|| this->syn_ready.find(mp(INADDR_ANY, nowsock->port)) != this->syn_ready.end())
	{
		this->returnSystemCall(sysid, -EADDRINUSE);
	}
	if(nowsock->isBound == false)
	{
		this->returnSystemCall(sysid, -EOPNOTSUPP);
	}
	nowsock->backlog = backlog;
	nowsock->status = MYLISTEN;
	this->syn_ready[mp(nowsock->ip, nowsock->port)] = nowsock;
	this->returnSystemCall(sysid, 0);
}

void TCPAssignment::syscall_accept(UUID sysid, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
		return;
	}
	auto welcsock = this->fd_to_context[mp(pid, fd)];
	if(welcsock->status != MYLISTEN)
	{
		this->returnSystemCall(sysid, -EINVAL);
		return;
	}
	if(!welcsock->established.empty())
	{
		auto newsock = *(welcsock->established.begin());
		welcsock->established.erase(welcsock->established.begin());
		int newfd = this->createFileDescriptor(pid);
		newsock->fd = newfd;
		newsock->pid = pid;
		this->fd_to_context[mp(pid, newfd)] = newsock;
		welcsock->isAcceptBlocked = false;
		*addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in * clntaddr = (struct sockaddr_in *)addr;
		clntaddr->sin_family = AF_INET;
		clntaddr->sin_port = newsock->peerport;
		clntaddr->sin_addr.s_addr = newsock->peerip;
		this->srcdest_to_context[mt(newsock->ip, newsock->port, newsock->peerip, newsock->peerport)] = newsock;
		this->returnSystemCall(sysid, newfd);
	}
	else
	{
		welcsock->isAcceptBlocked = true;
		welcsock->sysid = sysid;
		*addrlen = sizeof(struct sockaddr_in);
		welcsock->clntaddr = (struct sockaddr_in *)addr;
	}
}

void TCPAssignment::syscall_read(UUID sysid, int pid, int fd, void * buf, size_t count)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	auto cont = this->fd_to_context[mp(pid, fd)];	
	printf("read called with buf %p count %u\n", buf, count);
	if(cont->getReadSize() > 0)
	{
		puts("read handle immediately");
		unsigned int datasz = cont->getReadSize();
		if(count < datasz) datasz = count;
		cont->moveReceivedData(buf, datasz);
		cont->isReadBlocked = false;
		this->deleteReceived(cont, datasz);
		this->returnSystemCall(sysid, datasz);
		return;
	}
	else
	{
		puts("read handle blocked");
		cont->isReadBlocked = true;
		cont->sysid = sysid;
		cont->arg_buf = buf;
		cont->arg_cnt = count;
		return;
	}
}

void TCPAssignment::syscall_write(UUID sysid, int pid, int fd, void * buf, size_t count)
{
	if(this->fd_to_context.find(mp(pid, fd)) == this->fd_to_context.end())
	{
		this->returnSystemCall(sysid, -EBADF);
	}
	auto cont = this->fd_to_context[mp(pid, fd)];	



}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t ipcopy[4];	
	uint8_t tcp_seg[MSS + 54 + 10];
	int syn, ack, fin;
	unsigned char flags, dataoffset;	
	unsigned int myip, peerip, peerseq, peerack, datasz;
	unsigned short myport, peerport, peerchksum, chksum;
	MyTCPContext * welcsock = 0, * nowsock = 0;

	packet->readData(14+12, &peerip, 4);	
	packet->readData(14+16, &myip, 4);
	packet->readData(34+0, &peerport, 2);
	packet->readData(34+2, &myport, 2);
	packet->readData(34+13, &flags, 1);
	packet->readData(34+12, &dataoffset, 1);
	syn = !!(flags & (1 << 1));
	ack = !!(flags & (1 << 4));
	fin = !!(flags & 1);
	packet->readData(34+4, &peerseq, 4); peerseq = ntohl(peerseq);
	packet->readData(34+8, &peerack, 4); peerack = ntohl(peerack);
	packet->readData(34+16, &peerchksum, 2); peerchksum = ntohs(peerchksum);
	memset(tcp_seg, 0, sizeof(tcp_seg));
	packet->readData(34+0, tcp_seg, packet->getSize() - 34);
	*(unsigned short *)(tcp_seg + 16) = 0;
	chksum = ~NetworkUtil::tcp_sum(peerip, myip, tcp_seg, packet->getSize() - 34);
	// printf("1 offset %d packet size %d\n", dataoffset, packet->getSize());
	if(chksum != peerchksum)
	{
		this->freePacket(packet);
		return;
	}
	datasz = packet->getSize() - 54;
	// printf("2 offset %d packet size %d\n", dataoffset, packet->getSize());
	if(datasz > 0)//received some data
	{
		nowsock = this->findFromSrcdest(mt(myip, myport, peerip, peerport));
		puts("***********data detected");
		if(nowsock == 0) nowsock = this->findFromEstablished(mt(myip, myport, peerip, peerport));
		if(nowsock != 0)
		{
			if(nowsock->getReceivedSize() + packet->getSize() <= RECV_MAX_SIZE)
			{
				auto newpacket = this->allocatePacket(packet->getSize());
				char * temp = new char[packet->getSize()];
				packet->readData(0, temp, packet->getSize());
				newpacket->writeData(0, temp, packet->getSize());
				delete temp;
				nowsock->insertReceived(newpacket);
				if(nowsock->isReadBlocked && nowsock->getReadSize() > 0)
				{
					puts("read unblocking start");
					unsigned int datasz = nowsock->getReadSize();
					if (datasz > nowsock->arg_cnt) datasz = nowsock->arg_cnt;
					nowsock->moveReceivedData(nowsock->arg_buf, datasz);
					nowsock->isReadBlocked = false;
					this->deleteReceived(nowsock, datasz);
					this->returnSystemCall(nowsock->sysid, datasz);
				}
				
				auto ackpacket = this->allocatePacket(34+20);
				packet->readData(14+12, ipcopy, 4);
				ackpacket->writeData(14+16, ipcopy, 4);
				packet->readData(14+16, ipcopy, 4);
				ackpacket->writeData(14+12, ipcopy, 4);
				this->fillTCPHeader(tcp_seg, myport, peerport,
									nowsock->myseq, nowsock->myack,
									false, true, false, 0, RECV_MAX_SIZE - nowsock->getReceivedSize());
				chksum = ~NetworkUtil::tcp_sum(myip, peerip, tcp_seg, 20);
				*(unsigned short *)(tcp_seg + 16) = htons(chksum);
				ackpacket->writeData(34, tcp_seg, 20);
				this->sendPacket("IPv4", ackpacket);
				puts("***********sent ack for data");
			}
		}
	}

	if(syn == 1)//if(syn == 1 && ack == 0 && fin == 0)
	{
		welcsock = this->findFromSynready(mp(myip, myport));
		if((welcsock == 0)
		|| (welcsock->status != MYLISTEN && welcsock->status != SYNSENT)
		|| (welcsock->status == MYLISTEN && welcsock->backlog <= (int)welcsock->connecting.size()))
		{
			//Ignore SYN
		}
		else if(welcsock->status == MYLISTEN)
		{
			MyTCPContext * newsock = new MyTCPContext;
			newsock->peer_base_seq = peerseq;
			newsock->recvstart = peerseq + 1;
			newsock->recvend = peerseq + 1;
			newsock->setSeqAck(random(), peerseq+1, peerseq, peerack);
			newsock->setIpPort(myip, myport, peerip, peerport);
			newsock->isBound = true;
			newsock->status = SYNRCVD;
			welcsock->connecting.insert(newsock);
			auto synackpacket = this->allocatePacket(34+20);
			packet->readData(14+12, ipcopy, 4);
			synackpacket->writeData(14+16, ipcopy, 4);
			packet->readData(14+16, ipcopy, 4);
			synackpacket->writeData(14+12, ipcopy, 4);
			this->fillTCPHeader(tcp_seg, myport, peerport,
								newsock->myseq, newsock->myack,
								true, true, false, 0);
			chksum = ~NetworkUtil::tcp_sum(myip, peerip, tcp_seg, 20);
			*(unsigned short *)(tcp_seg + 16) = htons(chksum);
			synackpacket->writeData(34, tcp_seg, 20);
			this->sendPacket("IPv4", synackpacket);
			newsock->myseq++;
		}
		else if(welcsock->status == SYNSENT)//actually not welcoming socket
		{
			welcsock->peer_base_seq = peerseq;
			welcsock->recvstart = peerseq + 1;
			welcsock->recvend = peerseq + 1;
			//welcsock->setSeqAck(random(), peerseq+1, peerseq, peerack);
			welcsock->setSeqAck(welcsock->myseq, peerseq+1, peerseq, peerack);
			welcsock->setIpPort(myip, myport, peerip, peerport);
			welcsock->status = SYNRCVD;
			auto ackpacket = this->allocatePacket(34+20);
			packet->readData(14+12, ipcopy, 4);
			ackpacket->writeData(14+16, ipcopy, 4);
			packet->readData(14+16, ipcopy, 4);
			ackpacket->writeData(14+12, ipcopy, 4);
			this->fillTCPHeader(tcp_seg, myport, peerport,
								welcsock->myseq, welcsock->myack,
								false, true, false, 0);
			chksum = ~NetworkUtil::tcp_sum(myip, peerip, tcp_seg, 20);
			*(unsigned short *)(tcp_seg + 16) = htons(chksum);
			ackpacket->writeData(34, tcp_seg, 20);
			this->sendPacket("IPv4", ackpacket);
			this->syn_ready.erase(this->syn_ready.find(mp(welcsock->ip, welcsock->port)));
		}
	}
	if(ack)//else if(syn == 0 && ack == 1 && fin == 0)
	{
		nowsock = this->findFromSrcdest(mt(myip, myport, peerip, peerport));
		if(nowsock == 0) nowsock = this->findFromEstablished(mt(myip, myport, peerip, peerport));
		if(nowsock == 0)
		{
			welcsock = this->findFromSynready(mp(myip, myport));
			//ACK for SYNACK
			for(MyTCPContext * ptr : welcsock->connecting)
			{
				if(ptr->peerip == peerip && ptr->peerport == peerport && ptr->status == SYNRCVD)
				{
					nowsock = ptr;	break;
				}
			}
			if(nowsock != 0)
			{
			nowsock->status = ESTAB;			
			nowsock->peerack = peerack;
			nowsock->myseq = peerack;
			welcsock->connecting.erase(welcsock->connecting.find(nowsock));
			welcsock->established.insert(nowsock);
			if(welcsock->isAcceptBlocked == true)
			{
				auto newsock = *(welcsock->established.begin());
				welcsock->established.erase(welcsock->established.begin());
				int newfd = this->createFileDescriptor(welcsock->pid);
				newsock->fd = newfd;
				newsock->pid = welcsock->pid;
				this->fd_to_context[mp(welcsock->pid, newfd)] = newsock;
				this->srcdest_to_context[mt(newsock->ip, newsock->port, newsock->peerip, newsock->peerport)] = newsock;
				welcsock->isAcceptBlocked = false;
				welcsock->clntaddr->sin_family = AF_INET;
				welcsock->clntaddr->sin_port = newsock->peerport;
				welcsock->clntaddr->sin_addr.s_addr = newsock->peerip;
				this->returnSystemCall(welcsock->sysid, newfd);
			}
			}
		}
		else
		{
			nowsock->myseq = peerack;
			nowsock->peerack = peerack;
			switch(nowsock->status)
			{
				case FIN_WAIT_1:
					nowsock->status = FIN_WAIT_2;
					break;
				case CLOSING:
				{
					TimerPayload * payload = new TimerPayload;				
					nowsock->status = TIME_WAIT;
					payload->action = PAYLOAD_CLOSE;
					payload->sock = nowsock;
					nowsock->timer = this->addTimer((void *)payload, TIMEOUT);
				}
					break;
				case LAST_ACK:
					nowsock->status = CLOSED;
					this->close_cleanup(nowsock->sysid, nowsock->pid, nowsock->fd, nowsock);
					break;
				case SYNRCVD:
					nowsock->status = ESTAB;
					this->returnSystemCall(nowsock->sysid, 0);//return for connect()
					break;
				default:
					break;
			}
		}
		
	}
	if(fin)//else if(syn == 0 && ack == 0 && fin == 1)
	{
		nowsock = this->findFromSrcdest(mt(myip, myport, peerip, peerport));
		if(nowsock == 0) nowsock = this->findFromEstablished(mt(myip, myport, peerip, peerport));
		if(nowsock != 0)
		{
			bool sendACK = false;
			if(nowsock->isReadBlocked)
			{
				nowsock->isReadBlocked = false;
				this->returnSystemCall(nowsock->sysid , -1);
			}
			switch(nowsock->status)
			{
				case ESTAB:
					nowsock->peerseq = peerseq;
					nowsock->status = CLOSE_WAIT;
					sendACK = true;
					break;
				case FIN_WAIT_1:
					nowsock->peerseq = peerseq;
					nowsock->status = CLOSING;
					sendACK = true;
					break;
				case FIN_WAIT_2:
				{
					TimerPayload * payload = new TimerPayload;				
					nowsock->peerseq = peerseq;
					nowsock->status = TIME_WAIT;
					payload->action = PAYLOAD_CLOSE;
					payload->sock = nowsock;
					nowsock->timer = this->addTimer((void *)payload, TIMEOUT);
					sendACK = true;
				}
					break;
				default: break;
			}
			if(sendACK)
			{
				auto ackpacket = this->allocatePacket(34+20);
				packet->readData(14+12, ipcopy, 4);
				ackpacket->writeData(14+16, ipcopy, 4);
				packet->readData(14+16, ipcopy, 4);
				ackpacket->writeData(14+12, ipcopy, 4);
				nowsock->myack = nowsock->peerseq + 1;
				this->fillTCPHeader(tcp_seg, myport, peerport,
									nowsock->myseq, nowsock->myack,
									false, true, false, 0);
				chksum = ~NetworkUtil::tcp_sum(myip, peerip, tcp_seg, 20);
				*(unsigned short *)(tcp_seg + 16) = htons(chksum);
				ackpacket->writeData(34, tcp_seg, 20);
				this->sendPacket("IPv4", ackpacket);
			}
		}
	}
	this->freePacket(packet);
	return;		
}

void TCPAssignment::timerCallback(void* raw_payload)
{
	TimerPayload * payload = (TimerPayload *)raw_payload;
	if( payload->action == PAYLOAD_CLOSE )
	{
		auto nowsock = payload->sock;
		nowsock->status = CLOSED;
		this->close_cleanup(nowsock->sysid, nowsock->pid, nowsock->fd, nowsock);
		delete payload;
		return;
	}
}

void TCPAssignment::fillTCPHeader(uint8_t * tcp_seg, int srcport, int destport, int seqnum, int acknum, bool syn, bool ack, bool fin, int chksum, unsigned short window)
{
	memset(tcp_seg, 0, 20);
	*(unsigned short *)(tcp_seg + 0) = srcport;
	*(unsigned short *)(tcp_seg + 2) = destport;
	*(unsigned int *)(tcp_seg + 4) = htonl(seqnum);
	*(unsigned int *)(tcp_seg + 8) = htonl(acknum);
	*(unsigned char *)(tcp_seg + 12) = (5 << 4);
	int flag = 0;
	if(syn) flag += 1 << 1;
	if(ack) flag += 1 << 4;
	if(fin) flag += 1;
	*(unsigned char *)(tcp_seg + 13) = flag;
	*(unsigned short *)(tcp_seg + 14) = htons(window);
	*(unsigned short *)(tcp_seg + 16) = htons(chksum);
}

MyTCPContext * TCPAssignment::findFromSynready(std::pair<unsigned int, unsigned short> key)
{
	if(this->syn_ready.find(key) != this->syn_ready.end()) return this->syn_ready[key];
	key.first = INADDR_ANY;
	if(this->syn_ready.find(key) != this->syn_ready.end()) return this->syn_ready[key];
	return 0;
}

MyTCPContext * TCPAssignment::findFromSrcdest(std::tuple<unsigned int, unsigned short, unsigned int, unsigned short> key)
{
	if(this->srcdest_to_context.find(key) != this->srcdest_to_context.end()) return this->srcdest_to_context[key];
	/*
	srcdest에는 established 연결만 있고, 이 말은 concrete IP를 사용한다는 뜻
	std::get<0>(key) = INADDR_ANY;
	if(this->srcdest_to_context.find(key) != this->srcdest_to_context.end()) return this->srcdest_to_context[key];
	*/
	return 0;
}

MyTCPContext * TCPAssignment::findFromEstablished(std::tuple<unsigned int, unsigned short, unsigned int, unsigned short> key)
{
	auto welcsock = this->findFromSynready(mp(std::get<0>(key), std::get<1>(key)));
	if(welcsock != 0)
	{
		for(auto ptr : welcsock->established)
		{
			if(ptr->peerip == std::get<2>(key) && ptr->peerport == std::get<3>(key))
				return ptr;
		}
	}
	return 0;
}

unsigned int MyTCPContext::getReadSize()
{//read를 불렀을 때 정상적으로 얼마나 읽을 수 있는지(연속된 데이터)
	return this->recvend - this->recvstart;
}

unsigned int MyTCPContext::getReceivedSize()
{//현재 received에 저장된 패킷들 크기의 합
	unsigned int ret = 0;
	for(auto packet : this->received) ret += packet->getSize();
	return ret;
}
/*
void MyTCPContext::insertSent(Packet * packet)
{


}*/

void MyTCPContext::insertReceived(Packet * packet)
{//recvstart, recvend, myack도 책임져야 함
	unsigned int seq, datasz;
	unsigned int pseq, pdatasz;

	packet->readData(34+4, &pseq, 4); pseq = ntohl(pseq) - this->peer_base_seq;
	pdatasz = packet->getSize() - 54;

	auto it = this->received.begin();
	while(it != this->received.end())
	{
		(*it)->readData(34+4, &seq, 4); seq = ntohl(seq) - this->peer_base_seq;
		datasz = (*it)->getSize() - 54;
		if(seq + datasz > pseq + pdatasz) break;
		it++;
	}
	this->received.insert(it, packet);
	for(it = this->received.begin(); it != this->received.end(); it++)
	{
		(*it)->readData(34+4, &seq, 4); seq = ntohl(seq) - this->peer_base_seq;
		datasz = (*it)->getSize() - 54;
		if(seq <= this->recvend - this->peer_base_seq) this->recvend = std::max(this->recvend - this->peer_base_seq, seq + datasz) + this->peer_base_seq;
	}
	this->myack = this->recvend;
	printf("[%u, %u)\n", this->recvstart - this->peer_base_seq, this->recvend - this->peer_base_seq);
	int cnt = 0;
	for(it = this->received.begin(); it!=this->received.end();it++)
	{
		(*it)->readData(34+4, &seq, 4); seq = ntohl(seq) - this->peer_base_seq;
		datasz = (*it)->getSize() - 54;
		printf("%dth packet : [%u, %u)\n", cnt++, seq, seq+datasz);
	}
	printf("ack %u\n", this->myack - this->peer_base_seq);

}
/*
void TCPAssignment::deleteSent(MyTCPContext * cont)
{//내가 보낸 패킷 중 상대방한테 ACK을 받은 것은 sent 리스트에서 삭제


}*/

void TCPAssignment::deleteReceived(MyTCPContext * cont, size_t count)
{//내가 받은 패킷 중 count 만큼을 이번에 읽어서 다른 곳에 저장했으므로 received에서 연속된 count 만큼의 데이터를 가진 패킷들을 삭제
	assert(count <= cont->recvend - cont->recvstart);
	printf("deleteRcv with count %u\n", count);
	unsigned int seq, datasz;
	for(int i=0;i<1024;i++)//while(true)
	{
		auto it = cont->received.begin(); if(it == cont->received.end()) break;
		(*it)->readData(34+4, &seq, 4); seq = ntohl(seq) - cont->peer_base_seq;
		datasz = (*it)->getSize() - 54;
		printf("%d iter : packet with seq %u datasz %u list size %u\n", i, seq, datasz, cont->received.size()																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																												);
		if(seq + datasz <= cont->recvstart - cont->peer_base_seq + count)
		{
			printf("if with left %u right %u\n", seq + datasz, cont->recvstart - cont->peer_base_seq + count);
			this->freePacket(*it);
			cont->received.erase(it);
		}
		else if(seq < cont->recvstart - cont->peer_base_seq + count && cont->recvstart - cont->peer_base_seq + count < seq + datasz)
		{
			printf("elif with seq %u mid %u right %u\n", seq, cont->recvstart - cont->peer_base_seq + count ,seq+datasz);		
			auto cut = this->cutFrontData(*it, cont->recvstart+count-cont->peer_base_seq - seq);
			this->freePacket(*it);
			cont->received.erase(it);
			cont->received.push_front(cut);
		}
		else break;
	}
	cont->recvstart += count;
}

void MyTCPContext::moveReceivedData(void * buf, unsigned int count)
{//received에 저장된 데이터들 중 앞쪽 count 크기를 buf에 순서대로 쓴다
	printf("move called with %p, %u\n", buf, count);
	unsigned int seq, datasz;
	unsigned char temp;
	puts("move start");
	printf("recv seg : [%u ~ %u)\n", this->recvstart - this->peer_base_seq, this->recvend - this->peer_base_seq);
	for(auto it=this->received.begin(); it!=this->received.end(); it++)
	{
		(*it)->readData(34+4, &seq, 4); seq = ntohl(seq)- this->peer_base_seq;
		datasz = (*it)->getSize() - 54;
		//[recvstart, min(recvstart + count, seq + datasz))만큼을 count로 옮김
		printf("seq %u datasz %u\n", seq, datasz);
		for(unsigned int num = seq; num < seq + datasz; num++)
		{
			if(num < this->recvstart - this->peer_base_seq) continue;
			if(num >= this->recvstart - this->peer_base_seq + count) continue;
			printf("num %u\n", num);
			printf("read with %u, %u ptr %p\n", 54+num-seq, num+this->peer_base_seq-this->recvstart, ((char *)buf) + (num+this->peer_base_seq-this->recvstart));
			printf("packet info : size %u\n", (*it)->getSize());
			(*it)->readData(54+num-seq, &temp, 1);
			puts("temp passed");
			//warning : parenthesis must be kept since overflow of seq # affect pointer
			(*it)->readData(54+num-seq, ((char *)buf) + (num+this->peer_base_seq-this->recvstart), 1);
			printf("num %u end\n", num);
		}
		/*
		int l = std::max(this->recvstart- this->peer_base_seq, seq)-this->recvstart+ this->peer_base_seq;
		int r = std::min(this->recvstart- this->peer_base_seq+count, seq+datasz)-this->recvstart+ this->peer_base_seq;
		if(l>=r) continue;
		
		for(int i=l; i<r; i++)
		{
			(*it)->readData(54+i+this->recvstart-seq, ((char*)buf) + i, 1);
		}*/
	}
	puts("move end");
}

Packet * TCPAssignment::cutFrontData(Packet * packet, unsigned int count)
{//packet의 data 부분을 앞쪽 count 크기만큼 잘라낸 새로운 패킷을 반환
	printf("cutFrontData with packet size %u, count %u\n", packet->getSize(), count);
	unsigned int seq; printf("allocating size with %lu %u %d\n", packet->getSize()-count,packet->getSize()-count,packet->getSize()-count);
	auto newpacket = this->allocatePacket(packet->getSize() - count); puts("packet allocated");
	uint8_t * temp = new uint8_t[packet->getSize() - count]; puts("alloc success");
	packet->readData(0, temp, 54); puts("read 0");
	packet->readData(34+4, &seq, 4); seq = ntohl(seq); puts("read 1");
	*(unsigned int *)(temp + 34 + 4) = htonl(seq + count); puts("read 2");
	//TODO : modify new packet's checksum
	packet->readData(54 + count, temp + 54, packet->getSize() - 54 - count); puts("read 3");
	newpacket->writeData(0, temp, newpacket->getSize()); puts("write done");
	delete [] temp;
	puts("cutFrontData end");
	return newpacket;
}



}
