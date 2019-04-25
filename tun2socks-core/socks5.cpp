#include "socks5.h"

namespace tun2socks {

	AuthMethod::AuthMethod(SOCKS5METHOD method) : _method(method){}

	u_char AuthMethod::get_method() { return _method; }

	NoAuth::NoAuth() : AuthMethod(NO_AUTH) {}

	AUTHACTION NoAuth::next() { return SUCCESS; }

	std::unique_ptr<u_char[]> NoAuth::construct_send(size_t&) { return nullptr; }

	std::unique_ptr<u_char[]> NoAuth::construct_receive(size_t&) { return nullptr; }

	void NoAuth::sent() {return;}

	void NoAuth::received(const u_char*, size_t) { return; }

	PasswordAuth::PasswordAuth(const std::string& username, const std::string& password)
		: AuthMethod(USERNAME_PASSWORD), _username(username), _password(password), _next(SEND) {}

	PasswordAuth::PasswordAuth(const std::string&& username,const std::string&& password)
		: AuthMethod(USERNAME_PASSWORD), _username(std::move(username)), _password(std::move(password)), _next(SEND){}

	PasswordAuth::PasswordAuth(PasswordAuth&& o) : AuthMethod(o._method) {
		_next = o._next;
		o._next = SEND;
		_username = std::move(o._username);
		_password = std::move(o._password);
	}

	AUTHACTION PasswordAuth::next() {
		return _next;
	}

	std::unique_ptr<u_char[]> PasswordAuth::construct_send(size_t& len) {
		auto l_username = _username.size();
		auto l_password = _password.size();
		if (l_username > 255 || l_password > 255) {
			_next = FAILURE;
			return nullptr;
		}
		len = 3 + l_username + l_password;
		std::unique_ptr<u_char[]> p(new u_char[len]);
		p[0] = '\x01';
		p[1] = (u_char)l_username;
		memcpy(p.get() + 2, _username.c_str(), l_username);
		p[2 + l_username] = (u_char)l_password;
		memcpy(p.get() + 3 + l_username, _password.c_str(), l_password);
		return p;
	}

	std::unique_ptr<u_char[]> PasswordAuth::construct_receive(size_t& len) {
		len = 2;
		return std::unique_ptr<u_char[]>(new u_char[len]);
	}

	void PasswordAuth::sent() {
		_next = RECV;
	}

	void PasswordAuth::received(const u_char* buffer, size_t len) {
		if (len != 2) {
			_next = FAILURE;
			return;
		}
		else {
			if (buffer[0] != '\x01' || buffer[1] != '\x00')
				_next = FAILURE;
			else
				_next = SUCCESS;
			return;
		}
	}

	void PasswordAuth::reset() {
		_next = SEND;
	}

	Socks5Socket::Socks5Socket(boost::asio::io_context& ctx, std::unique_ptr<AuthMethod>&& auth)
		: _socket(ctx), _resolver(ctx), _strand(ctx),  _auth(std::move(auth)), _connected(false), _closed(true), _relayed(false), _ctx(ctx), _u_socket(ctx), _u_strand(ctx) {

	}

	bool Socks5Socket::connectProxy(const std::string& proxy_ip, uint16_t proxy_port) {
		if (!_connected) {
			boost::asio::ip::tcp::resolver::query q(proxy_ip.c_str(), std::to_string(proxy_port).c_str());
			auto results = _resolver.resolve(q);
			auto method = _auth->get_method();
			if (results.size() == 0)
				return false;
			_socket.connect(*(results.begin()));
			_closed = false;
			u_char hello_msg[3] = { '\x05', '\x01', (u_char)method };
			_socket.send(boost::asio::buffer(hello_msg, 3));
			u_char recv_msg[2];
			_socket.receive(boost::asio::buffer(recv_msg, 2));
			if (recv_msg[1] != method)
				return false;
			auto act = _auth->next();
			while (act != SUCCESS && act != FAILURE) {
				if (act == SEND) {
					size_t len;
					auto p = _auth->construct_send(len);
					_socket.send(boost::asio::buffer(p.get(), len));
					_auth->sent();
				}
				else if (act == RECV) {
					size_t len;
					auto p = _auth->construct_receive(len);
					_socket.receive(boost::asio::buffer(p.get(), len));
					_auth->received(p.get(), len);
				}
			}
			if (act == SUCCESS)
				_connected = true;
			else if (act == FAILURE)
				_connected = false;
			return _connected;
		}
		else
			return _connected;
	}

	bool Socks5Socket::associateUDP(uint32_t dst_ip, uint16_t port) {
		if (_relayed)
			return _relayed;
		auto request = _construct_request(COMMAND::UDP_ASSOCIATE, dst_ip, port);
		uint8_t buffer[1600];
		size_t recved;
		try {
			_socket.send(boost::asio::buffer(request.data(), request.len()));
			recved = _socket.receive(boost::asio::buffer(buffer, 1600));
		}
		catch (std::exception& e) {
			printf("socks5 associate udp:%s\n", e.what());
			_relayed = false;
			return false;
		}
		if (recved < 7 || buffer[0] != '\x05' || buffer[1] != '\x00' || buffer[2] != '\x00' || buffer[3] != ADDRESS_TYPE::IPV4) {
			_relayed = false;
			return _relayed;
		}
		auto u_bnd_addr = *((uint32_t*)(&buffer[4]));
		auto u_bnd_port = *((uint16_t*)(&buffer[8]));
		_u_bnd = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(ntohl(u_bnd_addr)), ntohs(u_bnd_port));
		_relayed = true;
		_u_socket.open(boost::asio::ip::udp::v4());
		_u_socket.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
		return _relayed;
	}

	bool Socks5Socket::connect(const std::string& domain, uint16_t port) {
		if (port > 65535)
			return false;
		auto request = _construct_request(COMMAND::CONNECT, domain, htons(port));
		u_char buffer[1600];
		size_t recved;
		try {
			_socket.send(boost::asio::buffer(request.data(), request.len()));
			recved = _socket.receive(boost::asio::buffer(buffer, 1600));
		}
		catch (std::exception& e) {
			printf("socks5 connect recv:%s\n", e.what());
			return false;
		}
		if (recved >= 7 && buffer[0] == '\x05' && buffer[1] == REPLY::SUCCEED)
			return true;
		else
			return false;
	}

	void Socks5Socket::async_send(std::shared_ptr<u_char> buffer, size_t len, std::function<send_handler> handler) {
		_socket.async_send(boost::asio::buffer(buffer.get(), len), _strand.wrap(handler));
	}

	void Socks5Socket::async_recv(std::shared_ptr<u_char> buffer, size_t len, std::function<recv_handler> handler) {
		_socket.async_receive(boost::asio::buffer(buffer.get(), len), _strand.wrap(handler));
	}

	void Socks5Socket::async_recvfrom(std::shared_ptr<u_char> buffer, size_t len, std::function<recv_handler> handler) {
		_u_socket.async_receive_from(boost::asio::buffer(buffer.get(), len), _u_bnd, _u_strand.wrap(handler));
	}

	void Socks5Socket::async_recvfrom(u_char* buf, size_t len, std::function<recv_handler> handler) {
		_u_socket.async_receive_from(boost::asio::buffer(buf, len), _u_bnd, [buf, len, handler](const boost::system::error_code& err, std::size_t recv_len) {
			if (err) {
				handler(err, 0);
				return;
			}
			if (recv_len < 7)
				return;
			if (buf[0] != 0 || buf[1] != 0 || buf[2] != 0)
				return;
			size_t start = 0;
			switch ((ADDRESS_TYPE)(buf[3])) {
			case IPV4:
				start = 10;
				break;
			case DOMAINNAME:
				start = buf[4] + 7;
				break;
			case IPV6:
				start = recv_len; // we don't support this.
				break;
			};
			if (start == 0 || start >= recv_len)
				return;
			memmove(buf, buf + start, recv_len - start);
			handler(err, recv_len - start);
		});
	}

	void Socks5Socket::async_sendto(std::shared_ptr<u_char> buffer, size_t len, uint32_t dst_ip, uint16_t port, std::function<send_handler> handler) {
		auto buf = std::make_shared<Buffer<u_char>>(std::move(_construct_udp_request(dst_ip, port, buffer.get(), len)));
		_u_socket.async_send_to(
			boost::asio::buffer(buf->data(), buf->len()),
			_u_bnd, 
			_u_strand.wrap([buf, handler](const boost::system::error_code& err, std::size_t len) {handler(err, len);}));
	}

	void Socks5Socket::async_sendto(std::shared_ptr<u_char> buffer, size_t len, const std::string& address, uint16_t port, std::function<send_handler> handler) {
		auto buf = std::make_shared<Buffer<u_char>>(std::move(_construct_udp_request(address, port, buffer.get(), len)));
		_u_socket.async_send_to(
			boost::asio::buffer(buf->data(), buf->len()),
			_u_bnd,
			_u_strand.wrap([buf, handler](const boost::system::error_code& err, std::size_t len) {handler(err, len); }));
	}

	void Socks5Socket::close() {
		boost::system::error_code ec;
		_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
		_socket.close();
	}

	void Socks5Socket::udp_close() {
		if (_relayed) {
			boost::system::error_code ec;
			_u_socket.shutdown(boost::asio::ip::udp::socket::shutdown_both, ec);
			_u_socket.close();
		}
	}

	void Socks5Socket::async_close() {
		if (!_closed) {
			_closed = true;
			auto self = shared_from_this();
			_strand.post([this, self]() {
				close();
			});
		}
	}

	void Socks5Socket::async_udp_close() {
		auto self = shared_from_this();
		_strand.post([this, self]() {
			udp_close();
		});
	}

	Buffer<uint8_t> Socks5Socket::_construct_request(COMMAND cmd,ADDRESS_TYPE type, const uint8_t* address, size_t address_len, uint16_t port) {
		Buffer<uint8_t> buffer(6 + address_len);
		buffer[0] = '\x05'; // version
		buffer[1] = cmd;
		buffer[2] = '\x00'; // reserved
		buffer[3] = type;
		memcpy(buffer.data() + 4, address, address_len);
		memcpy(buffer.data() + 4 + address_len, &port, 2);
		return buffer;
	}

	Buffer<uint8_t> Socks5Socket::_construct_request(COMMAND cmd, uint32_t ip, uint16_t port) {
		return _construct_request(cmd, ADDRESS_TYPE::IPV4, (uint8_t*)(&ip), 4, port);
	}

	Buffer<uint8_t> Socks5Socket::_construct_request(COMMAND cmd, const std::string& address, uint16_t port) {
		auto len = address.length();
		if (len > 0xFF)
			return Buffer<uint8_t>();
		auto new_address_bytes = (char)(len) + address;
		return _construct_request(cmd, ADDRESS_TYPE::DOMAINNAME, (uint8_t*)new_address_bytes.c_str(), new_address_bytes.length(), port);
	}

	Buffer<uint8_t> Socks5Socket::_construct_udp_request(ADDRESS_TYPE type, const uint8_t* address, size_t address_length, uint16_t port, const uint8_t* data, size_t data_len) {
		Buffer<uint8_t> buffer(6 + address_length + data_len);
		buffer[0] = '\x00'; // reserved
		buffer[1] = '\x00'; // reserved
		buffer[2] = '\x00'; // no fragmentation
		buffer[3] = type;
		memcpy(buffer.data() + 4, address, address_length);
		memcpy(buffer.data() + 4 + address_length, &port, 2);
		memcpy(buffer.data() + 6 + address_length, data, data_len);
		return buffer;
	}

	Buffer<uint8_t> Socks5Socket::_construct_udp_request(uint32_t ip, uint16_t port, const uint8_t* data, size_t data_len) {
		return _construct_udp_request(ADDRESS_TYPE::IPV4, (uint8_t*)&ip, 4, port, data, data_len);
	}

	Buffer<uint8_t> Socks5Socket::_construct_udp_request(const std::string& domain, uint16_t port, const uint8_t* data, size_t data_len) {
		return _construct_udp_request(ADDRESS_TYPE::DOMAINNAME, (uint8_t*)(domain.c_str()), domain.length(), port, data, data_len);
	}
}