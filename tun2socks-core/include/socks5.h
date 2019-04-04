#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <memory>

#include "socks5_auth.h"

namespace tun2socks {

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
		PasswordAuth(const std::string&&, const std::string&&);
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

		Socks5Socket(boost::asio::io_context&, std::unique_ptr<AuthMethod>&&);
		bool connectProxy(const std::string&, uint16_t);
		bool connect(const std::string&, uint16_t);
		void async_send(std::shared_ptr<u_char>, size_t, std::function<send_handler>);
		void async_recv(std::shared_ptr<u_char>, size_t, std::function<recv_handler>);
		void close();
		void async_close();
		
	private:
		std::unique_ptr<AuthMethod> _auth;
		boost::asio::ip::tcp::socket _socket;
		boost::asio::ip::tcp::resolver _resolver;
		boost::asio::io_service::strand _strand;
		bool _connected;
		bool _closed;
	};
}