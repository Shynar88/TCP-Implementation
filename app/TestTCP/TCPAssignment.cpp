/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

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

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:{
		// param1 - domain, 2 - type, 3 - protocol 
		// parameter checking
		if (param.param1_int != AF_INET) {
			printf("not IPv4, wrong protocol family\n"); //TODO: make normal error handling if required by tests
			// EAFNOSUPPORT = errno 
			this->returnSystemCall(syscallUUID, -1);
		} 
		if (param.param2_int != SOCK_STREAM) {
			printf("not stream communication type"); //TODO: make normal error handling if required by tests EPROTOTYPE
			this->returnSystemCall(syscallUUID, -1);
		} 
		if (param.param3_int != IPPROTO_TCP) {
			printf("not TCP socket"); //TODO: make normal error handling if required by tests EPROTONOSUPPORT
			this->returnSystemCall(syscallUUID, -1);
		} 

		// get fd
		int fd;
		if ((fd = this->createFileDescriptor(pid)) != -1) {
			//TODO: add information about socket to global data structures for future sys calls
			auto sckt_info = new Socket_info;
			sckt_info->domain = param.param1_int;
			sckt_info->socket_bound = false;
			sckt_info->pid = pid;
			this->fd_socket_map[fd] = sckt_info;
		} else {
			this->returnSystemCall(syscallUUID, -1); //TODO: make normal error handling EMFILE
		}
		
		// return on success
		this->returnSystemCall(syscallUUID, fd);
		break;
	}
	case CLOSE:{
		
		if(param.param1_int == -1){
			printf("problem while creating socket");
			this->returnSystemCall(syscallUUID, -1);
		}
		
		auto fpv = this->fd_socket_map.find(param.param1_int);
		if(fpv != this->fd_socket_map.end()){
			auto sckt_info = fpv->second;
			if(sckt_info->socket_bound == true){
				//close->send packet Finbit =1 and get answer
 				//after opponent send Findbit, wait some time, and it will be closed
				Packet* closepacket = allocatePacket(54);
				//Ethernet Frame
				//closepacket->writeData(0,  ,6);
				//closepacket->writeData(6,  ,6);
				uint8_t v[2] = {8, 0}; // ipv4
				closepacket->writeData(12, v ,2);
				//IP header
				uint8_t length[1] = {65}; // ipv4, header length = 20}
				closepacket->writeData(14, length ,1);

				uint8_t frag[2] = {4, 0}; //can't fragmentation
				closepacket->writeData(20, frag ,2);		

				uint8_t t[1] = {6}; //tcp
				closepacket->writeData(23, t ,1);
				/*
				uint8_t sourceip[4] = ntohl(sckt_info->addr->sin_addr.s_addr); //sourceip
				closepacket->writeData(26, sourceip ,4);
				uint8_t destip[4] = ntohl(sckt_info->remote_addr->sin_addr.s_addr); //destinationip
				closepacket->writeData(30, destip ,4);
				//TCP HEADER
				uint8_t sourceport[2] = ntohs(sckt_info->addr->sin_port); //sourceport
				closepacket->writeData(34, sourceport ,2);
				uint8_t destport[2] = ntohs(sckt_info->remote_addr->sin_port); //destinationip
				closepacket->writeData(36, destport ,2);
				*/
				struct sockaddr_in *addr = sckt_info->addr;
				uint16_t port = ntohs(addr->sin_port);
				uint32_t ip = ntohl(addr->sin_addr.s_addr);
				auto tpl = this->port_ip_map.find(port);
				if (tpl != this->port_ip_map.end()) { //port exists in map
					port_ip_map[port].erase(ip);
					if(port_ip_map[port].empty()){//if there's no ip in set, remove port
						port_ip_map.erase(port);
					}
				}
			}
		}
		fd_socket_map.erase(param.param1_int);
		//when success
		this->removeFileDescriptor(pid, param.param1_int);//close the fd with pid and fd value
		this->returnSystemCall(syscallUUID, param.param1_int);
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		
		break;
	}
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT: {
		struct sockaddr_in *addr_in = (struct sockaddr_in *) param.param2_ptr;
		uint16_t port = ntohs(addr_in->sin_port);
		uint32_t ip = ntohl(addr_in->sin_addr.s_addr);
		for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
			// checking if such socket exists
			if (tpl->first == param.param1_int && tpl->second->pid == pid){ //checking for fd and pid
				Socket_info *socket = tpl->second;
				//socket not bound
				if (!(socket->socket_bound)) {
					// client socket making implicit bind
					// create set of occupied ports 
					std::set<uint16_t> occupied_ports;
					for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++) {
						if (tpl->second->socket_bound && (tpl->second->addr->sin_addr.s_addr == htonl(INADDR_ANY) || tpl->second->addr->sin_addr.s_addr == htonl(ip))) {
							occupied_ports.insert(tpl->second->addr->sin_port);
						}
					}
					// get first available port > 1024
					uint16_t rand_port = 0;
					for (int i = 1025; i < 65536; i++){
						const bool occupied = occupied_ports.find(i) != occupied_ports.end();
						if (!occupied){
							rand_port = (uint16_t) i;
							break;
						}
					}
					if (rand_port == 0){
						// no ports available
						returnSystemCall(syscallUUID, -1);
						return;
					}

					Host *host = getHost();
					uint32_t buf = htonl(ip);
					int rout_port = host->getRoutingTable((uint8_t *) &buf);
					host->getIPAddr((uint8_t *) &buf, rout_port);
					struct sockaddr_in saddr;
					saddr.sin_addr.s_addr = htonl(buf);
					saddr.sin_port = htons(rand_port);
					socket->addr = static_cast<struct sockaddr_in *> (&saddr);
					// socket->addr->sin_addr.s_addr = htonl(buf); //set IP uint32_t
					// socket->addr->sin_port = htons(rand_port); //set Port uint16_t
					socket->socket_bound = true;
				}

				socket->syscallUUID = syscallUUID;
				socket->state = SYN_SENT;
				struct sockaddr_in saddr;
				saddr.sin_addr.s_addr = htonl(ip);
				saddr.sin_port = htons(port);
				socket->remote_addr = static_cast<struct sockaddr_in *> (&saddr);
				socket->addr_peer = static_cast<struct sockaddr *>(param.param2_ptr);
				socket->len_peer = param.param3_int;

				//write packet and send it 
				Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
				//fill the header 
				uint8_t hdr[20];
				memset(hdr, 0, 20);
				uint16_t l_port = htons(socket->addr->sin_port);
				uint16_t r_port = htons(socket->remote_addr->sin_port);
				uint32_t l_ip = htonl(socket->addr->sin_addr.s_addr);
				uint32_t r_ip = htonl(socket->remote_addr->sin_addr.s_addr);
				uint32_t seq_n = htonl(socket->sequence_num);
				// local port first
				memcpy(hdr, &l_port, 2); //uint16_t
				// remote port
				memcpy(hdr + 2, &r_port, 2); //uint16_t
				// sequence number
				memcpy(hdr + 4, &seq_n, 4); //uint32_t
				// // acknowledgment number 
				// memcpy(hdr + 8, htonl(0), 4); //uint32_t
				// flags
				uint16_t flags = 0x5;
				flags <<= 12;
				flags |= 0x0002; //SYN
				uint16_t nflags = htons(flags);
				memcpy(hdr + 12, &nflags, 2); //uint16_t
				// window field goes here hdr + 14, 2 bytes uint16_t
				// // checksum
				// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

				pckt->writeData(26, &l_ip, 4); //local ip
				pckt->writeData(30, &r_ip, 4); //remote ip
				pckt->writeData(34, hdr, 20); //header
				this->sendPacket("IPv4", pckt);
				socket->sequence_num += 1;
			}
		}
		// such socket doesn't exist
		returnSystemCall(syscallUUID, -1);
		return;
		//1: syscallID, 2: pid, 3: socket file descriptor 4: sockaddr, 5: socklen
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	}
	case LISTEN: {
	    // 1: syscallUUID, 2: pid, 3: fd, 4: backlog
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
			// checking if such socket exists
			if (tpl->first == param.param1_int && tpl->second->pid == pid){ //checking for fd and pid
				Socket_info *socket = tpl->second;
				socket->state = PASSIVE_SCKT;
				socket->listen_info = (struct Listen_info *) calloc(1, sizeof(struct Listen_info));
				if (!(socket->listen_info)) {
					//calloc failed
					returnSystemCall(syscallUUID, -1);
					return;
				}
				socket->listen_info->backlog = param.param2_int;
				socket->listen_info->pend_num = 0;
				socket->listen_info->wait_num = 0;
				//success
				returnSystemCall(syscallUUID, 0);
			}
		}
		// such socket doesn't exist
		returnSystemCall(syscallUUID, -1);
		return;
		break;
	}
	case ACCEPT: {
		//1: syscallUUID, 2: pid, 3: fd, 4: sockaddr, 5: socklen
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	}
	case BIND:{
		//1-sockfd, 2-sockaddr, 3-addrlen
		//search for fd in map
		auto tpl = this->fd_socket_map.find(param.param1_int);
		if (tpl != this->fd_socket_map.end()) {
			auto sckt_info = tpl->second; 
			if (sckt_info->socket_bound) {
				this->returnSystemCall(syscallUUID, -1); //EINVAL
			}
			struct sockaddr_in *addr = static_cast<struct sockaddr_in *>(param.param2_ptr);
			uint16_t port = ntohs(addr->sin_port);
			uint32_t ip = ntohl(addr->sin_addr.s_addr);
			auto tpl = this->port_ip_map.find(port);
			if (tpl != this->port_ip_map.end()) { //port exists in map
				if ((ip == INADDR_ANY) && (!port_ip_map[port].empty())) {
					this->returnSystemCall(syscallUUID, -1); //EADDRINUSE error
				} else if (port_ip_map[port].find(INADDR_ANY) != port_ip_map[port].end()) { //at this moment we check whether INADDR_ANY is in set
					this->returnSystemCall(syscallUUID, -1); //EADDRINUSE error
				}
				// at this point there should be no overlap, so add ip to the set of that port
				port_ip_map[port].insert(ip);
			} else { //port is not in the map, then no overlap
				port_ip_map.insert(std::pair<uint16_t, std::set<uint32_t>>(port, {ip}));
			}
			sckt_info->addr = static_cast<struct sockaddr_in *>(param.param2_ptr);
			sckt_info->addr2 = static_cast<struct sockaddr *>(param.param2_ptr);
			sckt_info->len = param.param3_int;
			sckt_info->socket_bound = true;
		} else {
			//failure
			this->returnSystemCall(syscallUUID, -1); //EBADF error
		}
		//success
		this->returnSystemCall(syscallUUID, 0);
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		break;
	}
	case GETSOCKNAME:{
		
		auto fpv = this->fd_socket_map.find(param.param1_int);
		if(fpv != this->fd_socket_map.end()){
			auto sckt_info = fpv->second;
			for(int i=0;i<14;i++){
				static_cast<struct sockaddr *>(param.param2_ptr)->sa_data[i] = sckt_info->addr2->sa_data[i];
			}
			static_cast<struct sockaddr *>(param.param2_ptr)->sa_family = sckt_info->addr2->sa_family;
			
			*static_cast<socklen_t*>(param.param3_ptr) = sckt_info->len;
		}else{
			//failure
			printf("can't find that socket");
			this->returnSystemCall(syscallUUID, -1);
		}

		
		//when success
		this->returnSystemCall(syscallUUID, 0);
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	}
	case GETPEERNAME:{
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		auto fpv = this->fd_socket_map.find(param.param1_int);
		if(fpv != this->fd_socket_map.end()){
			auto sckt_info = fpv->second;
			for(int i=0;i<14;i++){
				static_cast<struct sockaddr *>(param.param2_ptr)->sa_data[i] = sckt_info->addr_peer->sa_data[i];
			}
			static_cast<struct sockaddr *>(param.param2_ptr)->sa_family = sckt_info->addr_peer->sa_family;
			
			*static_cast<socklen_t*>(param.param3_ptr) = sckt_info->len_peer;
		}

		this->returnSystemCall(syscallUUID, 0);
		break;
	}
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//should handle following cases
	//Wrong Checksum
	// SYN:  clinet:SYNACK, server: SYN
	// FIN 
	// ACK
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
