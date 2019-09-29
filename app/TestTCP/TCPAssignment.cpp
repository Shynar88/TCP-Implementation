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
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
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
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
