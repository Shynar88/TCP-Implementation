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
	fd_socket_map.clear();
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
			//sckt_info->addr = &sckt_info->addr_help;
			sckt_info->addr_help.sin_port = 0;
			sckt_info->addr_help.sin_addr.s_addr = 0;
			sckt_info->addr_help.sin_family = AF_INET;
			sckt_info->remote_addr_help.sin_port = 0;
			sckt_info->remote_addr_help.sin_addr.s_addr = 0;
			sckt_info->remote_addr_help.sin_family = AF_INET;
			//sckt_info->remote_addr = &sckt_info->remote_addr_help;
			sckt_info->domain = param.param1_int;
			sckt_info->socket_listen = false;
			sckt_info->socket_bound = false;
			sckt_info->socket_others = false;
			sckt_info->socket_connected = false;
			sckt_info->read_called = 0; // changed
			sckt_info->read_packetarrived = 0;
			sckt_info->packet_left = 0;
			sckt_info->ack_received = false;
			sckt_info->write_num = 0;


			sckt_info->myclose = false;
			sckt_info->close_return = false;
			sckt_info->myclose_return = false;
			sckt_info->pid = pid;
			this->fd_socket_map[fd] = sckt_info;
		} else {
			this->returnSystemCall(syscallUUID, -1); //TODO: make normal error handling EMFILE
			return;
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
				if(sckt_info->socket_connected == true || sckt_info->socket_listen == true){
					//close->send packet Finbit =1 and get answer
 					//after opponent send Findbit, wait some time, and it will be closed
					
					Packet* closepacket = allocatePacket(54);
					uint32_t sourceip = sckt_info->addr_help.sin_addr.s_addr; //sourceip
					closepacket->writeData(26, &sourceip ,4);
					uint32_t destip = sckt_info->remote_addr_help.sin_addr.s_addr; //destinationip
					closepacket->writeData(30, &destip ,4);

					uint16_t sourceport = sckt_info->addr_help.sin_port; //sourceport
					closepacket->writeData(34, &sourceport ,2);
					uint16_t destport = sckt_info->remote_addr_help.sin_port; //destinationip
					closepacket->writeData(36, &destport ,2);
					uint32_t sqen = sckt_info->latest_ack_num;
					sqen = htonl(sqen);
					closepacket->writeData(38 , &sqen, 4);
					uint16_t close_flag = 0x0005;
					close_flag <<= 12;
					close_flag |= 0x0001; //Fin
					close_flag = htons(close_flag);
					closepacket->writeData(46, &close_flag, 2);
					uint16_t wins = htons(51200);
					closepacket->writeData(48, &wins, 2);


					size_t size = 20; 
					uint8_t buffer[size];
					closepacket->readData(34, buffer, size);
					uint16_t cs = ~NetworkUtil::tcp_sum(sourceip, destip, buffer, size);
					cs = htons(cs);
					closepacket->writeData(50, &cs, 2);



					sendPacket("IPv4", closepacket);
					sckt_info->myclose = true;
					sckt_info->close_pid = pid;
					sckt_info->close_fd = param.param1_int;
					sckt_info->closesyscallUUID = syscallUUID;
				}
				else{
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
					fd_socket_map.erase(param.param1_int);
					//when success
					this->removeFileDescriptor(pid, param.param1_int);//close the fd with pid and fd value
					this->returnSystemCall(syscallUUID, param.param1_int);
				}
			}
			else{
				fd_socket_map.erase(param.param1_int);
				//when success
				this->removeFileDescriptor(pid, param.param1_int);//close the fd with pid and fd value
				this->returnSystemCall(syscallUUID, param.param1_int);
			}
		}
		
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		
		break;
	}
	case READ:{
	
		auto fpv = this->fd_socket_map.find(param.param1_int);
		if(fpv != this->fd_socket_map.end()){
			auto sckt_info = fpv->second;
			if(sckt_info->packet_left!=0){	
				
				int re = param.param3_int;
				uint16_t read_length;
				
				sckt_info->read_pk->pk->readData(16, &read_length, 2);
				
				read_length = ntohs(read_length) - 40;
				uint16_t left = sckt_info->packet_left;
				
				if(re < left){
					sckt_info->read_pk->pk->readData(54+read_length-left, (uint8_t *) param.param2_ptr, re);

					sckt_info->packet_left = sckt_info->packet_left - re;
					this->returnSystemCall(syscallUUID, re);
				}
				else{
					sckt_info->read_pk->pk->readData(54+read_length-left, (uint8_t *) param.param2_ptr, left);

					sckt_info->packet_left = 0;
					sckt_info->read_pk = sckt_info->read_pk->next;
					
					sckt_info->read_packetarrived = sckt_info->read_packetarrived - 1;
					
					this->returnSystemCall(syscallUUID, left);

				}


				
			}
			else if(sckt_info->read_packetarrived == 0){
				int num = sckt_info->read_called;
				if(num == 0){
					
					struct Read_information *r = (struct Read_information *) calloc(1, sizeof(struct Read_information));
					/*
					sckt_info->read_info->syscallUUID = syscallUUID;
					sckt_info->read_info->pid = pid;
					sckt_info->read_info->add = param.param2_ptr;
					sckt_info->read_info->remain = param.param3_int;	
					*/
					//r.syscallUUID = syscallUUID;
					//r.pid = pid;
					//r.add = (uint8_t *) param.param2_ptr;
					r->pid = pid;
					r->syscallUUID = syscallUUID;
					r->add = (uint8_t *) param.param2_ptr;
					r->remain = param.param3_int;
					
					sckt_info->read_info = r;
					//printf("bbbbbbbbb : %p \n", r.add);
					//r.remain = param.param3_int;
					//sckt_info->read_info = &r;
				}
				else{
					
					struct Read_information *info = sckt_info->read_info;
					for(int i = 0; i < num-1; i++){
						info = info->next;
					}
					struct Read_information *r = (struct Read_information *) calloc(1, sizeof(struct Read_information));
					r->pid = pid;
					r->syscallUUID = syscallUUID;
					r->add = (uint8_t *) param.param2_ptr;
					r->remain = param.param3_int;
					info->next = r;
				}
				
				sckt_info->read_called = sckt_info->read_called + 1;

			}
			else{
			
				Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes

				uint16_t read_length;
				sckt_info->read_pk->pk->readData(16, &read_length, 2);
				read_length = ntohs(read_length) - 40;

				uint32_t src_ip_n;
				uint32_t dest_ip_n;
				uint16_t src_port_n;
				uint16_t dest_port_n;
				sckt_info->read_pk->pk->readData(26, &src_ip_n, 4);
				sckt_info->read_pk->pk->readData(30, &dest_ip_n, 4);
				sckt_info->read_pk->pk->readData(34, &src_port_n, 2);
				sckt_info->read_pk->pk->readData(36, &dest_port_n, 2);


				pckt->writeData(30, &src_ip_n, 4);
				pckt->writeData(26, &dest_ip_n, 4);
				pckt->writeData(36, &src_port_n, 2);
				pckt->writeData(34, &dest_port_n, 2);
				
				uint16_t read_flag = 0x0005;
				read_flag <<= 12;
				read_flag |= 0x0010; //ACK
				read_flag = htons(read_flag);
				pckt->writeData(46, &read_flag, 2);
				
				//42->ack 38->seq
				uint32_t ack_num;
				sckt_info->read_pk->pk->readData(38, &ack_num, 4);
				ack_num = ntohl(ack_num) + read_length;
				ack_num = htonl(ack_num);
				pckt->writeData(42, &ack_num, 4);
				
				uint32_t seq_num;
				sckt_info->read_pk->pk->readData(42, &seq_num, 4);
				pckt->writeData(38, &seq_num, 4); 
								
				

				int re = param.param3_int;
				if(re > 512){
					sckt_info->read_pk->pk->readData(54, (uint8_t *) param.param2_ptr, read_length);
				}
				else{
					if(read_length>re){
						sckt_info->read_pk->pk->readData(54, (uint8_t *) param.param2_ptr, re);
					}
					else{
						sckt_info->read_pk->pk->readData(54, (uint8_t *) param.param2_ptr, read_length);
					}
				}


				
				if(re<read_length){
					sckt_info->packet_left = read_length-re;

				}
				else{
					sckt_info->read_pk = sckt_info->read_pk->next;
					sckt_info->read_packetarrived = sckt_info->read_packetarrived - 1;
				}

				uint16_t wins = htons(51200-sckt_info->packet_left);
				pckt->writeData(48, &wins, 2);
				
				
				size_t size = 20; 
				uint8_t buffer[size];
				pckt->readData(34, buffer, size);
				uint16_t cs = ~NetworkUtil::tcp_sum(dest_ip_n, src_ip_n, buffer, size);
				cs = htons(cs);
				pckt->writeData(50, &cs, 2);
				this->sendPacket("IPv4", pckt);



				if(re > 512){
					this->returnSystemCall(syscallUUID, read_length);
				}
				else{
					if(read_length>re){
						this->returnSystemCall(syscallUUID, re);
					}
					else{
						this->returnSystemCall(syscallUUID, read_length);
					}
				}
				
			}
		}

		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	}
	case WRITE:{

		auto fpv = this->fd_socket_map.find(param.param1_int);
		if(fpv != this->fd_socket_map.end()){
			auto sckt_info = fpv->second;
			if(param.param3_int>=512){
				Packet* writepacket = allocatePacket(54+512);

				uint32_t sourceip = sckt_info->addr_help.sin_addr.s_addr; //sourceip
				writepacket->writeData(26, &sourceip ,4);

				uint32_t destip = sckt_info->remote_addr_help.sin_addr.s_addr; //destinationip
				writepacket->writeData(30, &destip ,4);

				uint16_t sourceport = sckt_info->addr_help.sin_port; //sourceport
				writepacket->writeData(34, &sourceport ,2);

				uint16_t destport = sckt_info->remote_addr_help.sin_port; //destinationip
				writepacket->writeData(36, &destport ,2);

				uint32_t sqen = sckt_info->write_seq;
				sqen = htonl(sqen);
				writepacket->writeData(38 , &sqen, 4);
				sckt_info->write_seq = sckt_info->write_seq+512;

				uint32_t ackn = sckt_info->write_ack;
				ackn = htonl(ackn);
				writepacket->writeData(42 , &ackn, 4);


				uint16_t write_flag = 0x0005;
				write_flag <<= 12;
				write_flag |= 0x0010;

				write_flag = htons(write_flag);
				writepacket->writeData(46, &write_flag, 2);

				uint16_t wins = htons(51200);
				writepacket->writeData(48, &wins, 2);
				
				
				writepacket->writeData(54, param.param2_ptr, 512);
				
				size_t size = 20+512; 
				uint8_t buffer[size];
				writepacket->readData(34, buffer, size);
				uint16_t cs = ~NetworkUtil::tcp_sum(sourceip, destip, buffer, size);
				cs = htons(cs);
				writepacket->writeData(50, &cs, 2);

				//struct Read_packet *r = (struct Read_packet *) calloc(1, sizeof(struct Read_packet));
				//r->

				this->sendPacket("IPv4", writepacket);
				
				this->returnSystemCall(syscallUUID, 512);

							

			}
			else if(param.param3_int<0){
				this->returnSystemCall(syscallUUID, -1);
			}
			else{
				Packet* writepacket = allocatePacket(54+param.param3_int);
				uint32_t sourceip = sckt_info->addr_help.sin_addr.s_addr; //sourceip
				writepacket->writeData(26, &sourceip ,4);

				uint32_t destip = sckt_info->remote_addr_help.sin_addr.s_addr; //destinationip
				writepacket->writeData(30, &destip ,4);

				uint16_t sourceport = sckt_info->addr_help.sin_port; //sourceport
				writepacket->writeData(34, &sourceport ,2);

				uint16_t destport = sckt_info->remote_addr_help.sin_port; //destinationip
				writepacket->writeData(36, &destport ,2);

				uint32_t sqen = sckt_info->write_seq;
				sqen = htonl(sqen);
				writepacket->writeData(38 , &sqen, 4);
				sckt_info->write_seq = sckt_info->write_seq+param.param3_int;

				uint32_t ackn = sckt_info->write_ack;
				ackn = htonl(ackn);
				writepacket->writeData(42 , &ackn, 4);

				uint16_t write_flag = 0x0005;
				write_flag <<= 12;
				write_flag |= 0x0010;

				write_flag = htons(write_flag);
				writepacket->writeData(46, &write_flag, 2);

				uint16_t wins = htons(51200);
				writepacket->writeData(48, &wins, 2);
				
				writepacket->writeData(54, param.param2_ptr, param.param3_int);



				size_t size = 20+param.param3_int; 
				uint8_t buffer[size];
				writepacket->readData(34, buffer, size);
				uint16_t cs = ~NetworkUtil::tcp_sum(sourceip, destip, buffer, size);
				cs = htons(cs);
				writepacket->writeData(50, &cs, 2);

				this->sendPacket("IPv4", writepacket);
				
				this->returnSystemCall(syscallUUID, param.param3_int);

									
			}
		}
		//printf("%d \n", param.param3_int);



		//this->returnSystemCall(syscallUUID, 131072);
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	}
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
					saddr.sin_addr.s_addr = buf;
					saddr.sin_port = htons(rand_port);
					saddr.sin_family = AF_INET;
					socket->ipipip = buf;
					socket->ptptpt = htons(rand_port);
					socket->addr = static_cast<struct sockaddr_in *> (&saddr);
					// socket->addr->sin_addr.s_addr = htonl(buf); //set IP uint32_t
					// socket->addr->sin_port = htons(rand_port); //set Port uint16_t
					
					socket->addr_help.sin_addr.s_addr = buf;					
					socket->addr_help.sin_port = htons(rand_port);
					socket->addr_help.sin_family = AF_INET;
					//socket->addr = &socket->addr_help;
					socket->socket_bound = true;
		
				}
				socket->syscallUUID = syscallUUID;
				socket->state = SYN_SENT;
				struct sockaddr_in saddr;
				saddr.sin_addr.s_addr = htonl(ip);
				saddr.sin_port = htons(port);
				socket->remote_addr_help.sin_port = addr_in->sin_port;
				socket->remote_addr_help.sin_addr.s_addr = addr_in->sin_addr.s_addr;
				socket->remote_addr_help.sin_family = addr_in->sin_family;
				socket->remote_addr = static_cast<struct sockaddr_in *> (addr_in);
									
			

					
				socket->len_peer = param.param3_int;
				socket->socket_connected = true;

				//write packet and send it 
				Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
				// flags
				uint16_t flags = 0x5;
				flags <<= 12;
				flags |= 0x0002; //SYN
				write_packet(pckt, socket->addr->sin_addr.s_addr, socket->addr->sin_port, socket->remote_addr->sin_addr.s_addr, socket->remote_addr->sin_port, socket->seq_num, socket->ack_num, flags, 51200);
				
				this->sendPacket("IPv4", pckt);
				socket->seq_num += 1;
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
				socket->socket_listen = true;
				socket->listen_info->backlog = param.param2_int;
				socket->listen_info->pend_num = 0;
				socket->listen_info->wait_num = 0;
				//success
				returnSystemCall(syscallUUID, 0);
			} else {
				// such socket doesn't exist
				returnSystemCall(syscallUUID, -1);
				return;
			}
		}
		break;
	}
	case ACCEPT: {
		
		//1: syscallUUID, 2: pid, 3: fd, 4: sockaddr, 5: socklen
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));

		
		

		for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
			
			// checking if such socket exists
			//if (tpl->first == param.param1_int && tpl->second->pid == pid){ //checking for fd and pid
			if (tpl->first == param.param1_int){ 
				Socket_info *socket = tpl->second;
				if (!(socket->state == PASSIVE_SCKT)) {
					// Socket is not a listening one
					returnSystemCall(syscallUUID, -1);
					return;
				}
				
				if (socket->listen_info->wait_num == 0) {
					
					//DEBUG
					// no waiting sockets
					socket->listen_info->pid = pid;
					socket->listen_info->syscallUUID = syscallUUID;
					socket->listen_info->sockaddr = static_cast<struct sockaddr_in*>(param.param2_ptr);
					socket->listen_info->socklen = static_cast<socklen_t*>(param.param3_ptr);
					
				}
				else {
					
					// handle waiting sockets
					// get next pending in queue, create new socket 
					int fd;
					if ((fd = this->createFileDescriptor(pid)) != -1) {
						auto new_socket = new Socket_info;
						struct Info_list *est_queue_el = socket->listen_info->est_queue; // need to check is struct is copied here or passed by reference
						socket->listen_info->est_queue = socket->listen_info->est_queue->next;
						socket->listen_info->wait_num -= 1;
						struct sockaddr_in saddr;
						saddr.sin_addr.s_addr = htonl(est_queue_el->ip);
						saddr.sin_port = htons(est_queue_el->port);
					
						saddr.sin_family = AF_INET;
						new_socket->remote_addr = static_cast<struct sockaddr_in *> (&saddr);

						new_socket->ack_received = true;

						struct sockaddr_in laddr;
						laddr.sin_addr.s_addr = htonl(est_queue_el->l_ip);
						laddr.sin_port = htons(est_queue_el->l_port);
						laddr.sin_family = AF_INET;
						new_socket->addr_help.sin_addr.s_addr = htonl(est_queue_el->l_ip);
						new_socket->addr_help.sin_port = htons(est_queue_el->l_port);
						new_socket->addr_help.sin_family = AF_INET;
						new_socket->addr = static_cast<struct sockaddr_in *> (&laddr);
						new_socket->ipipip = htonl(est_queue_el->l_ip);
						new_socket->ptptpt = htons(est_queue_el->l_port);
						new_socket->read_called = 0; // changed
						new_socket->read_packetarrived = 0;
						new_socket->packet_left=0;
						new_socket->write_num = 0;

						new_socket->socket_others = true;
						socket->remote_addr = static_cast<struct sockaddr_in *> (&laddr);
						
						static_cast<struct sockaddr_in*>(param.param2_ptr)->sin_family = AF_INET;
						static_cast<struct sockaddr_in*>(param.param2_ptr)->sin_addr.s_addr = laddr.sin_addr.s_addr;
						static_cast<struct sockaddr_in*>(param.param2_ptr)->sin_port = laddr.sin_port;
						
						new_socket->write_seq = socket->write_seq;
						new_socket->write_ack = socket->write_ack;

						new_socket->state = est_queue_el->state;
						new_socket->socket_bound = true;
						new_socket->pid = pid;
						new_socket->ack_num = est_queue_el->ack_num;
						new_socket->seq_num = est_queue_el->seq_num;
						new_socket->latest_ack_num = est_queue_el->seq_num;
						this->fd_socket_map[fd] = new_socket;
					
						free(est_queue_el);
					} else {
						this->returnSystemCall(syscallUUID, -1); //TODO: make normal error handling EMFILE
						return;
					}
					//success
					returnSystemCall(syscallUUID, fd);
					//return;
					
				}
			
			}
			else {
	
				// such socket doesn't exist
				returnSystemCall(syscallUUID, -1);
				return;
			}

			
		}
	
		break;
	}
	case BIND:{
		//1-sockfd, 2-sockaddr, 3-addrlen
		//search for fd in map
		auto tpl = this->fd_socket_map.find(param.param1_int);
		if (tpl != this->fd_socket_map.end()) {
			auto sckt_info = tpl->second; 
			// maybe need to check by pid also
			if (sckt_info->socket_bound) {
				this->returnSystemCall(syscallUUID, -1); //EINVAL
				return;
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
			
			sckt_info->len = param.param3_int;
			sckt_info->socket_bound = true;
		} else {
			//failure, no such socket
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
			if(sckt_info->socket_others){
				
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_family = AF_INET;
				//static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_port = sckt_info->ptptpt;
				//static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_addr.s_addr = ntohl(sckt_info->ipipip);
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_port = sckt_info->addr_help.sin_port;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_addr.s_addr = sckt_info->addr_help.sin_addr.s_addr;

	

			}
			else{
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_family = sckt_info->addr->sin_family;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_port = sckt_info->addr->sin_port;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_addr.s_addr = sckt_info->addr->sin_addr.s_addr;

			}
		
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
			if(sckt_info->socket_bound){
				//static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_family = sckt_info->remote_addr->sin_family;
				//static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_port = sckt_info->remote_addr->sin_port;
				//static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_addr.s_addr = sckt_info->remote_addr->sin_addr.s_addr;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_family = sckt_info->remote_addr_help.sin_family;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_port = sckt_info->remote_addr_help.sin_port;
				static_cast<struct sockaddr_in *>(param.param2_ptr)->sin_addr.s_addr = sckt_info->remote_addr_help.sin_addr.s_addr;
				
				
				*static_cast<socklen_t*>(param.param3_ptr) = sckt_info->len_peer;
				this->returnSystemCall(syscallUUID, 0);
			}
			else{
				returnSystemCall(syscallUUID, -1);

			}
		}

		
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
	if (true) {
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
			for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
				Socket_info *socket = tpl->second;
				if(socket->socket_bound){
					//bool rmt_ip_equal = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
					//bool rmt_port_equal = (socket->remote_addr->sin_port == src_port_n);
					bool lcl_ip_equal = (socket->addr->sin_addr.s_addr == dest_ip_n || socket->ipipip == dest_ip_n || socket->addr->sin_addr.s_addr == htonl(INADDR_ANY));
					bool lcl_port_equal = (socket->addr->sin_port == dest_port_n || socket->ptptpt == dest_port_n);
					if (lcl_ip_equal && lcl_port_equal){
						//send ACK to server to indicate that client received server's SYN ACK
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
					
						pckt->writeData(30, &src_ip_n, 4);
						pckt->writeData(26, &dest_ip_n, 4);
						pckt->writeData(36, &src_port_n, 2);
						pckt->writeData(34, &dest_port_n, 2);


						uint16_t close_flag = 0x0005;
						close_flag <<= 12;
						close_flag |= 0x0010; //ACK
						close_flag = htons(close_flag);
						pckt->writeData(46, &close_flag, 2);
						uint32_t ack_num;
						packet->readData(38, &ack_num, 4);
						ack_num = ntohl(ack_num) + 1;
						ack_num = htonl(ack_num);
						pckt->writeData(42, &ack_num, 4);						
						
						uint16_t wins = htons(51200);
						pckt->writeData(48, &wins, 2);


						size_t size = 20; 
						uint8_t buffer[size];
						pckt->readData(34, buffer, size);
						uint16_t cs = ~NetworkUtil::tcp_sum(dest_ip_n, src_ip_n, buffer, size);
						cs = htons(cs);
						pckt->writeData(50, &cs, 2);

					

						this->sendPacket("IPv4", pckt);
						//this->freePacket(pckt);
						//on success
						socket->close_return = true;
						if(socket->myclose_return){
						
							addTimer(NULL, 1);
							struct sockaddr_in *addr = socket->addr;
							int pid = socket->close_pid;
							int fd = socket->close_fd;
							uint16_t port = ntohs(addr->sin_port);
							uint32_t ip = ntohl(addr->sin_addr.s_addr);
							auto tpl = this->port_ip_map.find(port);
							if (tpl != this->port_ip_map.end()) { //port exists in map
								port_ip_map[port].erase(ip);
								if(port_ip_map[port].empty()){//if there's no ip in set, remove port		
									port_ip_map.erase(port);
								}
							}
							fd_socket_map.erase(fd);
						
							//when success
							this->removeFileDescriptor(pid, fd);//close the fd with pid and fd value
							this->returnSystemCall(socket->closesyscallUUID, 0);
						
						}
						
					}
				}
			}
			
		}
	
		// SYN
		if (syn) {
			if (ack) {
				// client receives SYN ACK from server
				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					//fix socket not bound bug put everything inside this loop 
					bool rmt_ip_equal;
					bool rmt_port_equal;
					bool lcl_ip_equal;
					bool lcl_port_equal;
					bool state_syn_sent = (socket->state == SYN_SENT);
					if (socket->socket_bound) {
					

						rmt_ip_equal = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
						rmt_port_equal = (socket->remote_addr->sin_port == src_port_n);
						lcl_ip_equal = (socket->ipipip == dest_ip_n);
						lcl_port_equal = (socket->ptptpt == dest_port_n);
						//lcl_ip_equal = (socket->addr->sin_addr.s_addr == dest_ip_n);
						//lcl_port_equal = (socket->addr->sin_port == dest_port_n);
						
					
					} else {
						rmt_ip_equal = false;
						rmt_port_equal = false;
						lcl_ip_equal = false;
						lcl_port_equal = false;
					}
					if (socket->socket_bound && rmt_ip_equal && rmt_port_equal && lcl_ip_equal && lcl_port_equal && state_syn_sent){
						packet->readData(42, &socket->write_seq, 4);
						packet->readData(38, &socket->write_ack, 4);;
						//send ACK to server to indicate that client received server's SYN ACK
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK
						uint32_t rcvd_ack_num;
						packet->readData(42, &rcvd_ack_num, 4);
						rcvd_ack_num = ntohl(rcvd_ack_num);
						socket->write_seq = rcvd_ack_num;

						socket->latest_ack_num = rcvd_ack_num;
						uint32_t ack_num;
						packet->readData(38, &ack_num, 4);
						ack_num = ntohl(ack_num) + 1;
						socket->write_ack = ack_num;
						
						socket->ack_num = ack_num;
						write_packet(pckt, dest_ip_n, dest_port_n, src_ip_n, src_port_n, socket->seq_num, socket->ack_num, flags, 51200);
				
						this->sendPacket("IPv4", pckt);
						this->freePacket(packet);
						socket->state = EST;
						socket->socket_connected = true;
						//on success
				
						returnSystemCall(socket->syscallUUID, 0);
						return;
					}
					if (socket->socket_bound && rmt_ip_equal && rmt_port_equal && lcl_ip_equal && lcl_port_equal){ 
						//send ACK to server to indicate that client received server's SYN ACK, but client already is not in SYN SENT state
						//write packet and send it 
						Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
						// flags
						uint16_t flags = 0x0005;
						flags <<= 12;
						flags |= 0x0010; //ACK


						uint32_t h;
						packet->readData(42, &h, 4);
						h = ntohl(h);
						socket->write_seq = h;


						uint32_t rcvd_ack_num;
						packet->readData(38, &rcvd_ack_num, 4);
						rcvd_ack_num = ntohl(rcvd_ack_num) + 1;
						socket->write_ack = rcvd_ack_num;

						write_packet(pckt, dest_ip_n, dest_port_n, src_ip_n, src_port_n, socket->seq_num, rcvd_ack_num, flags, 51200);
				
					
						this->sendPacket("IPv4", pckt);
						// this->freePacket(pckt);
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
									
									uint16_t flags = 0x0005;
									flags <<= 12;
									flags |= 0x0002; //SYN
									flags |= 0x0010; //ACK
									write_packet(pckt, dest_ip_n, dest_port_n, src_ip_n, src_port_n, list_elem->seq_num - 1, list_elem->ack_num, flags, 51200);
									
									this->sendPacket("IPv4", pckt);
									this->freePacket(packet);
									return;
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
							l_info->seq_num = socket->seq_num;
							socket->listen_info->syn_queue = l_info;
							socket->listen_info->pend_num += 1;

							//send packet 
							//write packet and send it 
							Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
							uint16_t flags = 0x0005;
							flags <<= 12;
							flags |= 0x0002; //SYN
							flags |= 0x0010; //ACK
							uint32_t rcvd_ack_num;
							packet->readData(38, &rcvd_ack_num, 4);
							rcvd_ack_num = ntohl(rcvd_ack_num)+1;
							l_info->ack_num = rcvd_ack_num;
							write_packet(pckt, dest_ip_n, dest_port_n, src_ip_n, src_port_n, l_info->seq_num, l_info->ack_num, flags, 51200);
		
							
							
							this->sendPacket("IPv4", pckt);
							l_info->seq_num += 1;
							this->freePacket(packet);
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
			// ==========================================================
			//for loop for handling closing connections
			uint16_t read_length;
			packet->readData(16, &read_length, 2);
			read_length = ntohs(read_length) - 40;
			if(read_length>0){

				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					if(socket->socket_bound){
						//bool rmt_ip_equal = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
						//bool rmt_port_equal = (socket->remote_addr->sin_port == src_port_n);
						bool lcl_ip_equal = (socket->addr_help.sin_addr.s_addr == dest_ip_n || socket->ipipip == dest_ip_n || socket->addr->sin_addr.s_addr == htonl(INADDR_ANY));
						bool lcl_port_equal = (socket->addr_help.sin_port == dest_port_n || socket->ptptpt == dest_port_n);
						if (lcl_ip_equal && lcl_port_equal){
							if(socket->read_called > 0){
							
								Packet *pckt = this->allocatePacket(54); //wireshark showed packet to be of size 54 bytes
								pckt->writeData(30, &src_ip_n, 4);
								pckt->writeData(26, &dest_ip_n, 4);
								pckt->writeData(36, &src_port_n, 2);
								pckt->writeData(34, &dest_port_n, 2);
				
								uint16_t read_flag = 0x0005;
								read_flag <<= 12;
								read_flag |= 0x0010; //ACK
								read_flag = htons(read_flag);
								pckt->writeData(46, &read_flag, 2);
				
								//42->ack 38->seq
								uint32_t ack_num;
								packet->readData(38, &ack_num, 4);
								ack_num = ntohl(ack_num) + read_length;
								ack_num = htonl(ack_num);
								pckt->writeData(42, &ack_num, 4);
				
								uint32_t seq_num;
								packet->readData(42, &seq_num, 4);
								pckt->writeData(38, &seq_num, 4); 
								


								
								int re = socket->read_info->remain;
								if(re > 512){
									packet->readData(54, socket->read_info->add, read_length);
								}
								else{
									if(read_length>re){
										packet->readData(54, socket->read_info->add, re);
									}
									else{
										packet->readData(54, socket->read_info->add, read_length);
									}
								}
								
								if(re<read_length){
									
									socket->packet_left = read_length-re;
									struct Read_packet *r = (struct Read_packet *) calloc(1, sizeof(struct Read_packet));
									r->pk = this->allocatePacket(read_length+54);
									uint8_t x[566];
									packet->readData(0, x, read_length+54);
								
									r->pk->writeData(0, x, read_length+54);
									socket->read_packetarrived = socket->read_packetarrived+1;
									socket->read_pk = r;
								}
								
								uint16_t wins = htons(51200-socket->packet_left);
								pckt->writeData(48, &wins, 2);
				
				
								size_t size = 20; 
								uint8_t buffer[size];
								pckt->readData(34, buffer, size);
								uint16_t cs = ~NetworkUtil::tcp_sum(dest_ip_n, src_ip_n, buffer, size);
								cs = htons(cs);
								pckt->writeData(50, &cs, 2);
								this->sendPacket("IPv4", pckt);


								UUID syscallUUID = socket->read_info->syscallUUID;
								
								socket->read_info = socket->read_info->next;
								socket->read_called = socket->read_called-1;
								
								


								if(re > 512){
									returnSystemCall(syscallUUID, read_length);
								}
								else{
									if(read_length>re){
										returnSystemCall(syscallUUID, re);
									}
									else{
										returnSystemCall(syscallUUID, read_length);
									}
									
								}

							
											
								
							}
							else{
								struct Read_packet *r = (struct Read_packet *) calloc(1, sizeof(struct Read_packet));
								r->pk = this->allocatePacket(read_length+54);
								uint8_t x[566];
								packet->readData(0, x, read_length+54);
								
								r->pk->writeData(0, x, read_length+54);
								int num = socket->read_packetarrived;
								if(num == 0){
									socket->read_pk = r;

								}
								else{
									struct Read_packet *info = socket->read_pk;
									for(int i = 0; i < num-1; i++){
										info = info->next;
									}
									info->next = r;

								}
								socket->read_packetarrived = socket->read_packetarrived+1;
										
							}		
						}
					}			
				}
			}
			else{
				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					if(socket->socket_bound){
						//bool rmt_ip_equal = (socket->remote_addr->sin_addr.s_addr == src_ip_n);
						//bool rmt_port_equal = (socket->remote_addr->sin_port == src_port_n);
						bool lcl_ip_equal = (socket->addr->sin_addr.s_addr == dest_ip_n);
						bool lcl_port_equal = (socket->addr->sin_port == dest_port_n);
						// if (rmt_ip_equal && rmt_port_equal && lcl_ip_equal && lcl_port_equal){ //DEBUG
						if (lcl_ip_equal && lcl_port_equal){
							
							if(socket->myclose){
								if(socket->close_return){
									struct sockaddr_in *addr = socket->addr;
									int pid = socket->close_pid;
									int fd = socket->close_fd;
									uint16_t port = ntohs(addr->sin_port);
									uint32_t ip = ntohl(addr->sin_addr.s_addr);
									auto tpl = this->port_ip_map.find(port);
									if (tpl != this->port_ip_map.end()) { //port exists in map	
										port_ip_map[port].erase(ip);
										if(port_ip_map[port].empty()){//if there's no ip in set, remove port		
											port_ip_map.erase(port);
										}
									}
									fd_socket_map.erase(fd);
									//when success
									this->removeFileDescriptor(pid, fd);//close the fd with pid and fd value
									this->returnSystemCall(socket->closesyscallUUID, 0);
								}
								socket->myclose_return = true;
							
							}
						
						}
					}
				}
				// ===================================================
				// for loop for handling opening connections
				
				for (auto tpl = fd_socket_map.begin(); tpl != fd_socket_map.end(); tpl++){
					Socket_info *socket = tpl->second;
					bool s_l_port_eq_d_port;
					bool s_l_ip_eq_d_ip;
					if (socket->socket_bound) {
						s_l_port_eq_d_port = (socket->addr->sin_port == dest_port_n);
						s_l_ip_eq_d_ip = (socket->addr->sin_addr.s_addr == dest_ip_n || socket->addr->sin_addr.s_addr == htonl(INADDR_ANY));
					} else {
						s_l_port_eq_d_port = false;
						s_l_ip_eq_d_ip = false;
					}
					if (socket->socket_bound && socket->state == PASSIVE_SCKT && s_l_port_eq_d_port && s_l_ip_eq_d_ip && socket->ack_received == false) {
						// handshaking 3rd step
						socket->ack_received = true;
						struct Info_list *prev_list_elem = NULL;
						struct Info_list *list_elem;
						uint32_t h;
						packet->readData(42, &h, 4);
						h = ntohl(h);
						socket->write_seq = h;

						
						uint32_t r;
						packet->readData(38, &r, 4);
						r = ntohl(r);
						socket->write_ack = r;

						for (list_elem = socket->listen_info->syn_queue; list_elem != NULL; list_elem = list_elem->next) {
							bool ip_equal = (list_elem->ip == src_ip);
							bool port_equal = (list_elem->port == src_port);
							if (ip_equal && port_equal) {
								socket->listen_info->pend_num -= 1;
								if (prev_list_elem != NULL) {
									prev_list_elem->next = list_elem->next;
								} else {
									socket->listen_info->syn_queue = list_elem->next;
								}

								if (!socket->listen_info->syscallUUID) {
									struct Info_list *l_info = (struct Info_list *) calloc(1, sizeof(struct Info_list));
									if (!(l_info)) {
										//calloc failed
										this->freePacket(packet);
										return;
									}
									//fill in listen_info
									l_info->ip = src_ip;
									l_info->port = src_port;
									
									l_info->l_ip = list_elem->l_ip;
									l_info->l_port = list_elem->l_port;
									l_info->seq_num = list_elem->seq_num;
									l_info->ack_num = list_elem->ack_num;
									
									//seq, ack num should be fixed here, and congestion management
									l_info->state = EST;
									l_info->next = socket->listen_info->est_queue;
									socket->listen_info->est_queue = l_info;
									socket->listen_info->wait_num += 1;
								
									
									this->freePacket(packet);
									free(list_elem);
									return;
								} else {
							
									// get fd for blocked accept
									int fd;
									if ((fd = createFileDescriptor(socket->listen_info->pid)) != -1) {
										auto sckt_info = new Socket_info;
										sckt_info->socket_bound = true;
										sckt_info->socket_connected = true;
										sckt_info->state = EST;
										
										sckt_info->write_seq = socket->write_seq;
										sckt_info->write_ack = socket->write_ack;

										sckt_info->ack_received = true;

										struct sockaddr_in addr2;
										addr2.sin_port = htons(list_elem->l_port);
										addr2.sin_addr.s_addr = htonl(list_elem->l_ip);
										addr2.sin_family = AF_INET; 
										sckt_info->addr = &addr2;
										sckt_info->addr_help.sin_port = htons(list_elem->l_port);
										sckt_info->addr_help.sin_addr.s_addr = htonl(list_elem->l_ip);
										sckt_info->addr_help.sin_family = AF_INET;
										//sckt_info->addr->sin_port = htons(list_elem->l_port);
										//sckt_info->addr->sin_addr.s_addr = htonl(list_elem->l_ip);
										struct sockaddr_in remote_addr2;
										remote_addr2.sin_port = src_port_n;
										remote_addr2.sin_addr.s_addr = src_ip_n;
										remote_addr2.sin_family = AF_INET;
										sckt_info->remote_addr = &remote_addr2;
										sckt_info->remote_addr_help.sin_port = src_port_n;
										sckt_info->remote_addr_help.sin_addr.s_addr = src_ip_n;
										sckt_info->remote_addr_help.sin_family = AF_INET;
										//sckt_info->remote_addr->sin_port = src_port_n;
										//sckt_info->remote_addr->sin_addr.s_addr = src_ip_n;
										sckt_info->read_called = 0;
										sckt_info->read_packetarrived = 0;
										sckt_info->packet_left = 0;
								
										sckt_info->write_num = 0;
										sckt_info->socket_others = true;
										sckt_info->seq_num = list_elem->seq_num;
										sckt_info->ack_num = list_elem->ack_num;
										sckt_info->latest_ack_num = list_elem->seq_num;
										//handle ack, seq numbers. maybe need window size for future kens
										this->fd_socket_map[fd] = sckt_info;
										socket->listen_info->sockaddr->sin_family = AF_INET;
										socket->listen_info->sockaddr->sin_port = sckt_info->remote_addr->sin_port;
										socket->listen_info->sockaddr->sin_addr.s_addr = sckt_info->remote_addr->sin_addr.s_addr;
										*(socket->listen_info->socklen) = sizeof(struct sockaddr_in);
										free(list_elem);
									} else {
										this->returnSystemCall(socket->listen_info->syscallUUID, -1); //TODO: make normal error handling EMFILE
										this->freePacket(packet);
										return;
									}
									
									// return on success
									this->returnSystemCall(socket->listen_info->syscallUUID, fd);
									this->freePacket(packet);
									return;
									break;
								}
							}
							prev_list_elem = list_elem;
						}
						this->freePacket(packet);
						return;
					}
				}
				this->freePacket(packet);
				return;
			}
		}

	} else {
		//incorrect checksum
		this->freePacket(packet);
		return;
	}

}

void TCPAssignment::timerCallback(void* payload)
{
	struct timespec t;
	struct timespec tt;
	t.tv_sec = 0;
	t.tv_nsec = 128000;
	tt.tv_sec = 0;
	tt.tv_nsec = 0;
	nanosleep(&t, &tt);
}

void TCPAssignment::write_packet(Packet *pckt, uint32_t l_ip, uint16_t l_port, uint32_t r_ip, uint16_t r_port, uint32_t seq_num, uint32_t ack_num, uint16_t flag, uint16_t window_size) {
	//fill the header 
	uint8_t hdr[20];
	memset(hdr, 0, 20);
	// uint16_t l_port = htons(l_port);
	// uint16_t r_port = htons(r_port);
	// uint32_t l_ip = htonl(l_ip);
	// uint32_t r_ip = htonl(r_ip);
	uint32_t seq_n = htonl(seq_num);
	uint32_t ack_n = htonl(ack_num);
	uint16_t nflags = htons(flag);
	uint16_t window_size_n = htons(window_size);
	// local port first
	memcpy(hdr, &l_port, 2); //uint16_t
	// remote port
	memcpy(hdr + 2, &r_port, 2); //uint16_t
	// sequence number
	memcpy(hdr + 4, &seq_n, 4); //uint32_t
	// acknowledgment number 
	memcpy(hdr + 8, &ack_n, 4); //uint32_t
	// flags
	memcpy(hdr + 12, &nflags, 2); //uint16_t
	// window field goes here hdr + 14, 2 bytes uint16_t, convert to htons
	memcpy(hdr + 14, &window_size_n, 2);
	// checksum
	uint16_t checksum = htons(~NetworkUtil::tcp_sum(l_ip, r_ip, hdr, 20));
	memcpy(hdr + 16, &checksum, 2); //uint16_t

	pckt->writeData(26, &l_ip, 4); //local ip
	pckt->writeData(30, &r_ip, 4); //remote ip
	pckt->writeData(34, hdr, 20); //header
}

}