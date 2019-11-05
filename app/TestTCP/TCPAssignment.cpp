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
			sckt_info->socket_connected = false;
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
				if(sckt_info->socket_connected == true){
					//close->send packet Finbit =1 and get answer
 					//after opponent send Findbit, wait some time, and it will be closed
					
					Packet* closepacket = allocatePacket(54);
				
					uint32_t sourceip = htonl(sckt_info->addr->sin_addr.s_addr); //sourceip
					closepacket->writeData(26, &sourceip ,4);
					uint32_t destip = htonl(sckt_info->remote_addr->sin_addr.s_addr); //destinationip
					closepacket->writeData(30, &destip ,4);

					uint16_t sourceport = htons(sckt_info->addr->sin_port); //sourceport
					closepacket->writeData(34, &sourceport ,2);
					uint16_t destport = htons(sckt_info->remote_addr->sin_port); //destinationip
					closepacket->writeData(36, &destport ,2);
				

					uint8_t flag[2] = {80, 1};//length is 20, fin = 1
					closepacket->writeData(46, flag, 2);
					sendPacket("IPv4", closepacket);
					NSLEEP;
				}
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
				socket->socket_connected = true;

				//write packet and send it 
				Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
				//fill the header 
				uint8_t hdr[20];
				memset(hdr, 0, 20);
				uint16_t l_port = htons(socket->addr->sin_port);
				uint16_t r_port = htons(socket->remote_addr->sin_port);
				uint32_t l_ip = htonl(socket->addr->sin_addr.s_addr);
				uint32_t r_ip = htonl(socket->remote_addr->sin_addr.s_addr);
				// uint32_t seq_n = htonl(socket->sequence_num);
				// local port first
				memcpy(hdr, &l_port, 2); //uint16_t
				// remote port
				memcpy(hdr + 2, &r_port, 2); //uint16_t
				// // sequence number
				// memcpy(hdr + 4, &seq_n, 4); //uint32_t
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
				// socket->sequence_num += 1;
			} else {
				// such socket doesn't exist
				returnSystemCall(syscallUUID, -1);
				return;
			}
		}
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
		for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
			// checking if such socket exists
			if (tpl->first == param.param1_int && tpl->second->pid == pid){ //checking for fd and pid
				Socket_info *socket = tpl->second;
				if (!(socket->state == PASSIVE_SCKT)) {
					// Socket is not a listening one
					returnSystemCall(syscallUUID, -1);
					return;
				}

				if (socket->listen_info->wait_num == 0) {
					// no waiting sockets
					socket->listen_info->pid = pid;
					socket->listen_info->syscallUUID = syscallUUID;
					socket->listen_info->sockaddr = static_cast<struct sockaddr_in*>(param.param2_ptr);
					socket->listen_info->socklen = static_cast<socklen_t*>(param.param3_ptr);
				} else {
					// handle waiting sockets
					// get next pending in queue, create new socket 
					int fd;
					if ((fd = this->createFileDescriptor(pid)) != -1) {
						auto socket = new Socket_info;
						struct Info_list *est_queue_el = socket->listen_info->est_queue; // need to check is struct is copied here or passed by reference
						socket->listen_info->est_queue = socket->listen_info->est_queue->next;
						socket->listen_info->wait_num -= 1;
						struct sockaddr_in saddr;
						saddr.sin_addr.s_addr = htonl(est_queue_el->ip);
						saddr.sin_port = htons(est_queue_el->port);
						socket->remote_addr = static_cast<struct sockaddr_in *> (&saddr);
						struct sockaddr_in laddr;
						laddr.sin_addr.s_addr = htonl(est_queue_el->l_ip);
						laddr.sin_port = htons(est_queue_el->l_port);
						socket->addr = static_cast<struct sockaddr_in *> (&laddr);
						socket->state = est_queue_el->state;
						socket->socket_bound = true;
						socket->pid = pid;
						this->fd_socket_map[fd] = socket;
						free(est_queue_el);
					} else {
						this->returnSystemCall(syscallUUID, -1); //TODO: make normal error handling EMFILE
						return;
					}
					//success
					returnSystemCall(syscallUUID, fd);
					return;
				}
			}
		}
		// such socket doesn't exist
		returnSystemCall(syscallUUID, -1);
		return;
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
	// SYN:  client:SYNACK, server: SYN
	// FIN 
	// ACK 
	uint16_t flag;
	packet->readData(46, &flag, 2);
	flag = ntohs(flag);
	int Fin = flag%2;
	int Syn = (flag/2)%2;
	int ack = (flag/16)%2;

	size_t size = packet->getSize() - 34; 
	uint8_t buffer[size];
	packet->readData(34, buffer, size);

	uint32_t src_ip_n;
	uint32_t dest_ip_n;
	uint16_t src_port_n;
	uint16_t dest_port_n;
	packet->readData(26, &src_ip_n, 4);
	packet->readData(30, &dest_ip_n, 4);
	packet->readData(34, &src_port_n, 2);
	packet->readData(36, &dest_port_n, 2);
	uint32_t src_ip = ntohl(src_ip_n);
	uint32_t dest_ip = ntohl(dest_ip_n);
	uint16_t src_port = ntohs(src_port_n);
	uint16_t dest_port = ntohs(dest_port_n);
	
	uint16_t checksum = ~NetworkUtil::tcp_sum(src_ip_n, dest_ip_n, buffer, size);
	if (htons(checksum) == 0) {
		//checksum check passed
		// SYN:  client:SYNACK, server: SYN
		uint16_t syn = flag & 0x0002;
		// FIN 
		uint16_t fin = flag & 0x0001;
		// ACK
		uint16_t ack = flag & 0x0010;
		// FIN
		if (fin) {
			//TODO for closing connection
		}

		// SYN
		if (syn) {
			if (ack) {
				// client receives SYN ACK from server
				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					bool rmt_ip_equal = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
					bool rmt_port_equal = (socket->remote_addr->sin_port == src_port_n);
					bool lcl_ip_equal = (socket->addr->sin_addr.s_addr == dest_ip_n);
					bool lcl_port_equal = (socket->addr->sin_port == dest_port_n);
					bool state_syn_sent = (socket->state == SYN_SENT);
					if (socket->socket_bound && rmt_ip_equal && rmt_port_equal && lcl_ip_equal && lcl_port_equal && state_syn_sent){
						//send ACK to server to indicate that client received server's SYN ACK
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						//fill the header 
						uint8_t hdr[20];
						memset(hdr, 0, 20);
						// uint32_t seq_n = htonl(socket->sequence_num);
						// local port first
						memcpy(hdr, &dest_port_n, 2); //uint16_t
						// remote port
						memcpy(hdr + 2, &src_port_n, 2); //uint16_t
						// // sequence number
						// memcpy(hdr + 4, &seq_n, 4); //uint32_t
						// // acknowledgment number 
						// memcpy(hdr + 8, htonl(0), 4); //uint32_t
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK
						uint16_t nflags = htons(flags);
						memcpy(hdr + 12, &nflags, 2); //uint16_t
						// window field goes here hdr + 14, 2 bytes uint16_t
						// // checksum
						// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

						pckt->writeData(26, &dest_ip_n, 4); //local ip
						pckt->writeData(30, &src_ip_n, 4); //remote ip
						pckt->writeData(34, hdr, 20); //header
						this->sendPacket("IPv4", pckt);
						this->freePacket(pckt);
						socket->state = EST;
						socket->is_connected = true;
						//on success
						returnSystemCall(socket->syscallUUID, 0);
						return;
					}
					if (socket->socket_bound && rmt_ip_equal && rmt_port_equal && lcl_ip_equal && lcl_port_equal){ 
						//send ACK to server to indicate that client received server's SYN ACK, but client already is not in SYN SENT state
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						//fill the header 
						uint8_t hdr[20];
						memset(hdr, 0, 20);
						// uint32_t seq_n = htonl(socket->sequence_num);
						// local port first
						memcpy(hdr, &dest_port_n, 2); //uint16_t
						// remote port
						memcpy(hdr + 2, &src_port_n, 2); //uint16_t
						// // sequence number
						// memcpy(hdr + 4, &seq_n, 4); //uint32_t
						// // acknowledgment number 
						// memcpy(hdr + 8, htonl(0), 4); //uint32_t
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK
						uint16_t nflags = htons(flags);
						memcpy(hdr + 12, &nflags, 2); //uint16_t
						// window field goes here hdr + 14, 2 bytes uint16_t
						// // checksum
						// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

						pckt->writeData(26, &dest_ip_n, 4); //local ip
						pckt->writeData(30, &src_ip_n, 4); //remote ip
						pckt->writeData(34, hdr, 20); //header
						this->sendPacket("IPv4", pckt);
						this->freePacket(pckt);
					}
				}

				this->freePacket(packet);
				return;
			} else {
				// SYN for server, means opening connection, should respond with syn ack if possible 
				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					if (!(socket->state == PASSIVE_SCKT)) {
						//do nothing for not listening socket
					} else {
						//listening socket
						bool lcl_ip_equal_or_inaddr = ((socket->addr->sin_addr.s_addr == dest_ip_n) || (socket->addr->sin_addr.s_addr == htonl(INADDR_ANY)));
						bool lcl_port_equal = (socket->addr->sin_port == dest_port_n);
						if (socket->socket_bound && lcl_ip_equal_or_inaddr && lcl_port_equal) {
							//if number of pending bigger than backlog, drop packet
							bool queue_full = (socket->listen_info->backlog <= socket->listen_info->pend_num);
							if (queue_full) {
								this->freePacket(packet);
								return; 
							}
							//check if already in pending list by list el ip == src_ip  el port == src_port. If it is, send synack again
							struct Info_list *list_elem;
							for (list_elem = socket->listen_info->syn_queue; list_elem != NULL; list_elem = list_elem->next) {
								bool ip_equal = (list_elem->ip == src_ip);
								bool port_equal = (list_elem->port == src_port);
								bool is_pending = (ip_equal && port_equal);
								if (is_pending) {
									//send packet 
									//write packet and send it 
									Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
									//fill the header 
									uint8_t hdr[20];
									memset(hdr, 0, 20);
									// uint32_t seq_n = htonl(socket->sequence_num);
									// local port first
									memcpy(hdr, &dest_port_n, 2); //uint16_t
									// remote port
									memcpy(hdr + 2, &src_port_n, 2); //uint16_t
									// // sequence number
									// memcpy(hdr + 4, &seq_n, 4); //uint32_t
									// // acknowledgment number 
									// memcpy(hdr + 8, htonl(0), 4); //uint32_t
									// flags
									uint16_t flags = 0x0005;
									flags <<= 12;
									flags |= 0x0002; //SYN
									flags |= 0x0010; //ACK
									uint16_t nflags = htons(flags);
									memcpy(hdr + 12, &nflags, 2); //uint16_t
									// window field goes here hdr + 14, 2 bytes uint16_t
									// // checksum
									// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

									pckt->writeData(26, &dest_ip_n, 4); //local ip
									pckt->writeData(30, &src_ip_n, 4); //remote ip
									pckt->writeData(34, hdr, 20); //header
									this->sendPacket("IPv4", pckt);
									this->freePacket(pckt);
								}
							} 
							//not pending yet
							struct Info_list * l_info = (struct Info_list *) calloc(1, sizeof(struct Info_list));
							if (!(l_info)) {
								//calloc failed
								this->freePacket(packet);
								return;
							}
							//fill in listen_info
							l_info->ip = src_ip;
							l_info->port = src_port;
							l_info->l_ip = dest_ip;
							l_info->l_port = dest_port;
							l_info->state = SYN_RECEIVED;
							l_info->next = socket->listen_info->syn_queue;
							socket->listen_info->syn_queue = l_info;
							socket->listen_info->pend_num += 1;

							//send packet 
							//write packet and send it 
							Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
							//fill the header 
							uint8_t hdr[20];
							memset(hdr, 0, 20);
							// uint32_t seq_n = htonl(socket->sequence_num);
							// local port first
							memcpy(hdr, &dest_port_n, 2); //uint16_t
							// remote port
							memcpy(hdr + 2, &src_port_n, 2); //uint16_t
							// // sequence number
							// memcpy(hdr + 4, &seq_n, 4); //uint32_t
							// // acknowledgment number 
							// memcpy(hdr + 8, htonl(0), 4); //uint32_t
							// flags
							uint16_t flags = 0x0005;
							flags <<= 12;
							flags |= 0x0002; //SYN
							flags |= 0x0010; //ACK
							uint16_t nflags = htons(flags);
							memcpy(hdr + 12, &nflags, 2); //uint16_t
							// window field goes here hdr + 14, 2 bytes uint16_t
							// // checksum
							// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

							pckt->writeData(26, &dest_ip_n, 4); //local ip
							pckt->writeData(30, &src_ip_n, 4); //remote ip
							pckt->writeData(34, hdr, 20); //header
							this->sendPacket("IPv4", pckt);
							this->freePacket(pckt);
							return;
						}
					}
				}

				this->freePacket(packet);
				return;
			}
		}

		// ACK
		if (ack) {
			//TODO should return returnSystemCall with saved syscallUUID from blocking syscalls
			// TODO increment waiting sockets stuff
			uint32_t rcvd_ack;
			rcvd_ack = ntohl(packet->readData(42, &rcvd_ack, 4));
			for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
				Socket_info *socket = tpl->second;
				bool s_l_port_eq_d_port = (socket->addr->sin_port == dest_port_n);
				bool s_l_ip_eq_d_ip = (socket->addr->sin_addr.s_addr == dest_ip_n || socket->addr->sin_addr.s_addr == htonl(INADDR_ANY));
				bool s_r_ip_eq_s_ip = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
				bool s_r_port_eq_s_port = (socket->remote_addr->sin_port == src_port_n);
				if (s_l_port_eq_d_port && s_l_ip_eq_d_ip && s_r_ip_eq_s_ip && s_r_port_eq_s_port && socket->socket_bound && socket->state == FIN_W_1) {
					// ACK FIN WAIT 1
					if (rcvd_ack != socket->latest_expected_ack) {
						//send packet 
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						//fill the header 
						uint8_t hdr[20];
						memset(hdr, 0, 20);
						// uint32_t seq_n = htonl(socket->sequence_num);
						// local port first
						memcpy(hdr, &socket->addr->sin_port, 2); //uint16_t
						// remote port
						memcpy(hdr + 2, &socket->remote_addr->sin_port, 2); //uint16_t
						// // sequence number, should substract 1!
						// memcpy(hdr + 4, &seq_n, 4); //uint32_t
						// // acknowledgment number 
						// memcpy(hdr + 8, htonl(0), 4); //uint32_t
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK
						uint16_t nflags = htons(flags);
						memcpy(hdr + 12, &nflags, 2); //uint16_t
						// window field goes here hdr + 14, 2 bytes uint16_t
						// // checksum
						// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

						pckt->writeData(26, &dest_ip_n, 4); //local ip
						pckt->writeData(30, &src_ip_n, 4); //remote ip
						pckt->writeData(34, hdr, 20); //header
						this->sendPacket("IPv4", pckt);
						this->freePacket(pckt);
						return;
					} else {
						// transfer to FIN WAIT 2
						this->freePacket(packet);
						socket->state = FIN_W_2;
						return;
					}
				} else if {
					// ACK last ack
				} else if {
					// ack after fin 
				} else if (socket->socket_bound && socket->state == CLOSING && s_l_port_eq_d_port && s_l_ip_eq_d_ip && s_r_ip_eq_s_ip && s_r_port_eq_s_port){
					// Closing ACK. CLient received ACK after FIN; change state, send nothing
					if (rcvd_ack != socket->latest_expected_ack) {
						//send packet 
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						//fill the header 
						uint8_t hdr[20];
						memset(hdr, 0, 20);
						// uint32_t seq_n = htonl(socket->sequence_num);
						// local port first
						memcpy(hdr, &socket->addr->sin_port, 2); //uint16_t
						// remote port
						memcpy(hdr + 2, &socket->remote_addr->sin_port, 2); //uint16_t
						// // sequence number, should substract 1!
						// memcpy(hdr + 4, &seq_n, 4); //uint32_t
						// // acknowledgment number 
						// memcpy(hdr + 8, htonl(0), 4); //uint32_t
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK
						uint16_t nflags = htons(flags);
						memcpy(hdr + 12, &nflags, 2); //uint16_t
						// window field goes here hdr + 14, 2 bytes uint16_t
						// // checksum
						// memcpy(hdr + 16, htons(~NetworkUtil::tcp_sum()), 2); //uint16_t

						pckt->writeData(26, &dest_ip_n, 4); //local ip
						pckt->writeData(30, &src_ip_n, 4); //remote ip
						pckt->writeData(34, hdr, 20); //header
						this->sendPacket("IPv4", pckt);
						this->freePacket(pckt);
						return;
					} else {

					}
				}
			}
			for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){

			}
			this->freePacket(packet);
			return;
		}

	} else {
		//incorrect checksum
		this->freePacket(packet);
		return;
	}

	uint16_t sn;
	packet->readData(38, &sn, 2);
	sn = sn+1;//sequence number+1
	Packet* myPacket = this->clonePacket(packet);
	myPacket->writeData(26, dest_ip, 4);
	myPacket->writeData(30, src_ip, 4);//change the destination and source ip
	myPacket->writeData(40, &sn, 2);//give the value to ack that sn+1
	

	



}

void TCPAssignment::timerCallback(void* payload)
{
	
}


}
