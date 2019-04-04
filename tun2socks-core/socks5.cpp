#include <socks5.h>

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
		: _socket(ctx), _resolver(ctx), _strand(ctx),  _auth(std::move(auth)), _connected(false), _closed(true) {

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

	bool Socks5Socket::connect(const std::string& domain, uint16_t port) {
		if (port > 65535)
			return false;
		u_char buffer[1600];
		buffer[0] = '\x05';
		buffer[1] = '\x01';
		buffer[2] = '\x00';
		buffer[3] = '\x03';
		buffer[4] = (u_char)domain.length();
		memcpy(buffer + 5, domain.c_str(), domain.length());
		auto port_n = htons(port);
		memcpy(buffer + 5 + domain.length(), &port_n, 2);
		_socket.send(boost::asio::buffer(buffer, 5 + domain.length() + 2));
		try {
			_socket.receive(boost::asio::buffer(buffer, 1600));
		}
		catch (std::exception& e) {
			printf("socks5 connect recv:%s\n", e.what());
		}
		if (buffer[1] == 0)
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

	void Socks5Socket::close() {
		boost::system::error_code ec;
		_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
		_socket.close();
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
}