/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

	
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	enum sct_state{
		//client
		EST,
		SYN_SENT,
		FIN_W_1,
		FIN_W_2,
		CLOSING,

		//server
		SYN_RECEIVED,
		PASSIVE_SCKT
	};

	struct Info_list {
		public:
			uint32_t l_ip;
			uint16_t l_port;
			uint32_t ip;
			uint16_t port;
			uint32_t ack_num;				
			uint32_t seq_num;
			sct_state state;
			Info_list *next;
	};

	struct Listen_info {
		public:
			//might need to store sockaddr
			int backlog;
			int pid;
			UUID syscallUUID;
			struct sockaddr_in* sockaddr;		
			socklen_t *socklen;	
			//SYN queue  state SYN RECEIVED pending
			int pend_num;
			Info_list *syn_queue; 
			//Accept queue state ESTABLISHED, it's when ACK packet in 3 way handshake received waiting
			int wait_num;
			Info_list *est_queue; 
	};

	struct payload_list {
		public:
			uint16_t s;
			uint32_t seq_num;
			bool sent;
			char *payload;
			struct payload_list *next;
			struct payload_list *prev;
	};
	struct Read_packet {
		public:
			Packet *pk;
			UUID syscallUUID;
			Read_packet *next;
	};
	struct Read_information {
		public:
			UUID syscallUUID;
			int pid;
			uint8_t *add;
			int remain;
			Read_information *next;
	};
	class Socket_info {
		public:
			int domain;
			int pid;
			// uint32_t sequence_num;
			struct sockaddr_in* remote_addr;
			struct sockaddr_in* addr;
			struct sockaddr_in addr_help;
			struct sockaddr_in remote_addr_help;

			struct Read_information *read_info;
			struct Read_packet *read_pk;
			int read_called;
			int read_packetarrived;			
			int packet_left; // changed
			

			int write_sent;
			int read_get;
			int this_turn;


			uint32_t write_seq;
			uint32_t write_ack;
			int write_num;


			uint32_t ipipip;
			uint16_t ptptpt;

			socklen_t len;
			socklen_t len_peer;
			bool socket_others;
			bool socket_listen;
			bool socket_bound;
			bool socket_connected;
			bool ack_received;

			bool myclose;
			bool close_return;
			bool myclose_return;
			UUID closesyscallUUID;
			int close_pid;
			int close_fd;
			UUID syscallUUID;
			// uncomment seq, ack num fields when needed
			uint32_t ack_num;					// from socket
			uint32_t seq_num;					// from socket, ++ on ACK
			uint32_t latest_ack_num; 			// socket receives it
			// uint32_t latest_expected_ack;		// FIN's ack num 
			// uint32_t latest_expected_seq_num; // FIN's seq num sent
			sct_state state;
			struct Listen_info* listen_info;
			struct payload_list* send_queue;
	};
	virtual void write_packet(Packet *packet, uint32_t l_ip, uint16_t l_port, uint32_t r_ip, uint16_t r_port, uint32_t seq_num, uint32_t ack_num, uint16_t flag, uint16_t window_size) final;
	std::map<int, Socket_info *> fd_socket_map;
	std::map<uint16_t, std::set<uint32_t>> port_ip_map;
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
