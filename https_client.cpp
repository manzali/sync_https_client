#include <iostream>
#include <istream>
#include <ostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/asio/ssl.hpp>

bool verify_certificate(
bool preverified, boost::asio::ssl::verify_context& context) {

  // In this example we will simply print the certificate's subject name.
  // Note that the callback is called once for each certificate in the
  // certificate chain, starting from the root certificate authority.

  char subject_name[256];
  X509* cert = X509_STORE_CTX_get_current_cert(context.native_handle());
  X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
  std::cout << "Verifying " << subject_name << std::endl;

  return preverified;
}

int main(int argc, char* argv[]) {

  try {

    // Define server and path
    std::string const server = "www.instagram.com";
    std::string const path = "/accounts/login/ajax/";
    std::string const parameters = "username=fewfw&password=fewfw";

    //while (1) {

      // Define request
      boost::asio::streambuf request;
      std::ostream request_stream(&request);
      request_stream << "POST " << path << " HTTP/1.1\r\n";
      request_stream << "Host: " << server << "\r\n";
      // User-Agent is not mandatory
      request_stream << "Accept: */*\r\n";
      // Accept-Language is not mandatory
      // Accept-Encoding is not mandatory
      request_stream << "X-CSRFToken: fqRL4xVdB6w0qBT7kqAqMVQeFIasCmkY\r\n";
      // Content-Type is not mandatory
      // X-Requested-With is not mandatory
      request_stream << "Referer: https://" << server << "/\r\n";
      request_stream << "Content-Length: " << parameters.size() << "\r\n";
      request_stream
        << "Cookie: csrftoken=fqRL4xVdB6w0qBT7kqAqMVQeFIasCmkY; mid=V-I19wAEAAG8pOV3FUjiNYJVw2Z-; ig_pr=2; ig_vw=1440\r\n";
      request_stream << "Connection: close\r\n\r\n";
      request_stream << parameters;

      // Create ssl context
      boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
      context.set_default_verify_paths();

      // Create io_service
      boost::asio::io_service io_service;

      // Create the boost system error code
      boost::system::error_code ec;

      // Creatre socket
      boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(
          io_service,
          context);

      // Get a list of endpoints corresponding to the server name
      boost::asio::ip::tcp::resolver resolver(io_service);
      boost::asio::ip::tcp::resolver::query query(server, "https");
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver
          .resolve(query, ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }
      std::cout << "Resolve OK" << std::endl;

      // Set the peer verification mode
      socket.set_verify_mode(boost::asio::ssl::verify_peer, ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }

      // Set the callback used to verify peer certificates
      socket.set_verify_callback(boost::bind(verify_certificate, _1, _2), ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }

      // Try each endpoint until we successfully establish a connection
      boost::asio::connect(socket.lowest_layer(), endpoint_iterator, ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }
      std::cout << "Connect OK" << std::endl;

      // Perform SSL handshaking
      socket.handshake(boost::asio::ssl::stream_base::client, ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }
      std::cout << "Handshake OK" << std::endl;

      // Print the request
      std::cout
        << "Print request:"
        << "\n****************************************\n"
        << boost::asio::buffer_cast<const char*>(request.data())
        << "\n****************************************"
        << std::endl;

      // Send the request
      boost::asio::write(socket, request, ec);
      if (ec) {
        // Error
        std::cout << ec.message() << std::endl;
        return -1;
      }
      std::cout << "Write OK" << std::endl;

      // Read the response status line. The response streambuf will automatically
      // grow to accommodate the entire line. The growth may be limited by passing
      // a maximum size to the streambuf constructor.
      boost::asio::streambuf response;
      boost::asio::read_until(socket, response, "\r\n");

      // Check that response is OK
      std::istream response_stream(&response);
      std::string http_version;
      response_stream >> http_version;
      unsigned int status_code;
      response_stream >> status_code;
      std::string status_message;
      std::getline(response_stream, status_message);
      if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
        std::cout << "Invalid response" << std::endl;
        return -1;
      }

      // Print the response status code
      std::cout
        << "Response returned with status code "
        << status_code
        << std::endl;

      // Read the response headers, which are terminated by a blank line
      boost::asio::read_until(socket, response, "\r\n\r\n");

      // Process the response headers
      std::string header;
      while (std::getline(response_stream, header) && header != "\r") {
        std::cout << header << std::endl;
      }
      std::cout << std::endl;

      // Write whatever content we already have to output
      if (response.size() > 0) {
        std::cout << &response;
      }

      // Read until EOF, writing data to output as we go
      while (boost::asio::read(
          socket,
          response,
          boost::asio::transfer_at_least(1),
          ec)) {
        std::cout << &response;
      }
      std::cout << std::endl;
      if (ec != boost::asio::error::eof) {
        throw boost::system::system_error(ec);
      }

    //}

  } catch (std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
  }

  return 0;
}
