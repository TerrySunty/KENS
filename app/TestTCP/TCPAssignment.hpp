/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <set>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <algorithm> 
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <E/Networking/E_Packet.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/E_TimerModule.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>

namespace E
{

const Time TIMEOUT = TimeUtil::makeTime(120,TimeUtil::SEC);
const Time RTT = TimeUtil::makeTime(100,TimeUtil::MSEC);
const Time RETRANS_TIMEOUT = TimeUtil::makeTime(100,TimeUtil::MSEC);
const unsigned int MSS = 512;
const unsigned int RECV_MAX_SIZE = 251212;
const unsigned int SEND_MAX_SIZE = 251212;

enum
{
	MYLISTEN,//0
	SYNSENT,//1
	ESTAB,//2
	SYNRCVD,//3
	FIN_WAIT_1,//4
	FIN_WAIT_2,//5
	TIME_WAIT,//6
	CLOSED,//7
	CLOSE_WAIT,//8
	CLOSING,//9
	LAST_ACK,//10
	PAYLOAD_CLOSE,//11
	PAYLOAD_DATA_RETRANSMIT,
	PAYLOAD_SYN_RETRANSMIT,
	PAYLOAD_FIN_RETRANSMIT
};

class MyTCPContext
{
	public:
	int fd, pid, backlog, status;
	uint32_t ip, peerip;
	uint16_t port, peerport;
	bool isBound, isAcceptBlocked, isReadBlocked, isWriteBlocked, isRetransTimerOn;
	UUID sysid, timer, retranstimer, syntimer, fintimer;
	unsigned int myseq, myack, peerseq, peerack;
	//내가 이번에 보낼 myseqnum, myacknum
	//내가 마지막으로 받은 peerseqnum, peeracknum
	unsigned int mymaxack, peermaxack;
	//내가 보낸 / 받은 ack중 가장 큰 것
	size_t arg_cnt;
	void * arg_buf;
	struct sockaddr_in * clntaddr;
	std::set<MyTCPContext *> connecting;
	std::set<MyTCPContext *> established;
	//received의 경우 받은 데이터의 끝부분이 더 큰게 더 뒤쪽에 있게,
	//sent의 경우 보낸 데이터의 끝부분이 더 큰게 더 뒤쪽에 있게
	std::list<Packet *> received;
	std::list<Packet *> sent;
	std::map<Packet *, UUID> packetTimer;
	//해당 패킷의 재전송을 위해 사용되는 타이머 아이디

	unsigned short peer_window_size;
	unsigned int peer_base_seq, my_base_seq, expectedMaxAck;
	unsigned int recvstart, recvend;
	unsigned int dupcnt;
	unsigned int fincnt;
	//[recvstart, recvend)가 현재 received 안에서 순서가 맞고, recvstart-1은 read 된 데이터 구간.

	MyTCPContext()
	{
		this->fd = this->pid = -1;
		ip = port = 0;
		peerip = peerport = 0;
		backlog = 0;
		sysid = 0;
		isAcceptBlocked = isReadBlocked = isWriteBlocked = false;
		this->isBound = false;
		this->status = CLOSED;
		this->myseq = this->myack = 0;
		this->peerseq = this->peerack = 0;
		this->peer_window_size = SEND_MAX_SIZE;
		this->dupcnt = 0;
		fincnt = 0;
	}
	void setSeqAck(unsigned int a, unsigned int b, unsigned int c, unsigned int d)
	{
		myseq = a; myack = b; peerseq = c; peerack = d;
	}
	void setIpPort(unsigned int a, unsigned short b, unsigned int c, unsigned short d)
	{
		ip = a; port = b; peerip = c; peerport = d;
	}
	unsigned int getReadSize();
	unsigned int getWriteSize();
	unsigned int getReceivedSize();
	unsigned int getSentSize();
	void insertReceived(Packet * packet);
	void insertSent(Packet * packet);
	
	void moveReceivedData(void * buf, unsigned int count);
};

class TimerPayload
{
	public:
	int action;
	MyTCPContext * sock;
	Packet * packet;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	//all ip and port are in Network Byte Order
	std::map<std::pair<int,int>, MyTCPContext *> fd_to_context;
	//myip, myport, peerip, peerport
	//find connected socket with src.dest info
	std::map<std::tuple<unsigned int, unsigned short, unsigned int, unsigned short>, MyTCPContext * > srcdest_to_context;
	std::map<std::pair<unsigned int, unsigned short>, MyTCPContext * > syn_ready;//to find welcoming sockets, if connected socket not exists
	std::set<std::pair<uint32_t, uint16_t> > bound_set; // cannot handle with 0.0.0.0
	std::map<uint16_t, std::set<uint32_t> > port_to_bound_ip;

private:
	virtual void timerCallback(void* payload) final;
	void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int fd_to_close);
	void close_cleanup(UUID syscallUUID, int pid, int fd_to_close, MyTCPContext *);
	void syscall_getsockname(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len);
	void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *, socklen_t);
	void syscall_connect(UUID sysid, int pid, int fd, struct sockaddr * addr, socklen_t len);
	void syscall_listen(UUID sysid, int pid, int fd, int backlog);
	void syscall_accept(UUID sysid, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen);
	void syscall_getpeername(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len);
	void syscall_read(UUID sysid, int pid, int fd, void * buf, size_t count);
	void syscall_write(UUID sysid, int pid, int fd, void * buf, size_t count);
	void fillTCPHeader(uint8_t * tcp_seg, int srcport, int destport, int seqnum, int acknum, bool syn, bool ack, bool fin, int chksum, unsigned short window=51212);
	MyTCPContext * findFromSrcdest(std::tuple<unsigned int, unsigned short, unsigned int, unsigned short> key);
	MyTCPContext * findFromSynready(std::pair<unsigned int, unsigned short> key);	
	MyTCPContext * findFromEstablished(std::tuple<unsigned int, unsigned short, unsigned int, unsigned short> key);
	void deleteReceived(MyTCPContext * cont, size_t count);
	void deleteSent(MyTCPContext * cont);
	Packet * cutFrontData(Packet * packet, unsigned int count);
	void addRetransmitTimer(MyTCPContext *);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
