#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <memory>

namespace tun2socks {

	enum SOCKS5METHOD:u_char {
		NO_AUTH = 0,
		USERNAME_PASSWORD = 2
	};

	enum AUTHACTION {
		SEND = 0,
		RECV,
		SUCCESS,
		FAILURE
	};

	class AuthMethod {
	protected:
		AuthMethod(SOCKS5METHOD);
		SOCKS5METHOD _method;
	public:
		u_char get_method();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&) = 0;
		virtual void sent() = 0;
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&) = 0;
		virtual void received(const u_char*, size_t) = 0;
		virtual AUTHACTION next() = 0;
	};


	class NoAuth: public AuthMethod {
	public:
		NoAuth();
		virtual AUTHACTION next();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&);
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&);
		virtual void sent();
		virtual void received(const u_char*, size_t);
	};

	class PasswordAuth : public AuthMethod {
	public:
		PasswordAuth(const std::string&, const std::string&);
		PasswordAuth(PasswordAuth&&);
		virtual AUTHACTION next();
		virtual std::unique_ptr<u_char[]> construct_send(size_t&);
		virtual std::unique_ptr<u_char[]> construct_receive(size_t&);
		virtual void sent();
		virtual void received(const u_char*, size_t);
		void reset();
	private:
		AUTHACTION _next;
		std::string _username;
		std::string _password;
	};
	

	class Socks5Socket : public std::enable_shared_from_this<Socks5Socket> {
	
	public:
		typedef void send_handler(const boost::system::error_code&, std::size_t);
		typedef void recv_handler(const boost::system::error_code&, std::size_t);

		Socks5Socket(boost::asio::io_context&, const std::string&, uint16_t, std::unique_ptr<AuthMethod>&&);
		bool connectProxy();
		bool connect(const std::string&, uint16_t);
		void async_send(std::shared_ptr<u_char>, size_t, std::function<send_handler>);
		void async_recv(std::shared_ptr<u_char>, size_t, std::function<recv_handler>);
		void close();
		void async_close();
		
	private:
		std::string _proxy_ip;
		std::unique_ptr<AuthMethod> _auth;
		unsigned int _proxy_port;
		size_t buffer_index;
		std::array<u_char, 256> buffer;
		boost::asio::ip::tcp::socket _socket;
		boost::asio::ip::tcp::resolver _resolver;
		boost::asio::io_service::strand _strand;
		bool _connected;
		bool _closed;
	};
}