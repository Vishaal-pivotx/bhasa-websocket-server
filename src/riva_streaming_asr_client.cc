#include <iostream>
#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>
typedef websocketpp::server<websocketpp::config::asio_tls> server;
using websocketpp::connection_hdl;
#include <csignal>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>

#include "bs64.h"
#include "client.h"
using namespace std;

using json = nlohmann::json;
std::vector<client*> connected_clients;
using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
typedef websocketpp::config::asio::message_type::ptr message_ptr;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
enum tls_mode { MOZILLA_INTERMEDIATE = 1, MOZILLA_MODERN = 2 };

std::array<std::string,6> xdm = {"name1","name2","name3","name4" ,"name5" ,"name6"};

bool g_request_exit = false;


class broadcast_server {
 public:
  broadcast_server()
  {
    m_server.set_access_channels(websocketpp::log::alevel::none);

    m_server.init_asio();
    
        m_server.set_tls_init_handler(
        bind(&broadcast_server::on_tls_init, this, MOZILLA_INTERMEDIATE, ::_1));
    m_server.set_open_handler(bind(&broadcast_server::on_open, this, ::_1));
    m_server.set_close_handler(bind(&broadcast_server::on_close, this, ::_1));
    m_server.set_message_handler(bind(&broadcast_server::on_message, this, ::_1, ::_2));
  }
  std::string get_password() { return "test"; }

  context_ptr on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl)
  {
    namespace asio = websocketpp::lib::asio;
    hdl.lock().get();

    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
      if (mode == MOZILLA_MODERN) {
        // Modern disables TLSv1
        ctx->set_options(
            asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 |
            asio::ssl::context::single_dh_use);
      } else {
        ctx->set_options(
            asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
            asio::ssl::context::no_sslv3 | asio::ssl::context::single_dh_use);
      }
      ctx->set_password_callback(bind(&broadcast_server::get_password, this));
      ctx->use_certificate_chain_file("server.pem");
      ctx->use_private_key_file("server.pem", asio::ssl::context::pem);

      ctx->use_tmp_dh_file("dh.pem");

      std::string ciphers;

      if (mode == MOZILLA_MODERN) {
        ciphers =
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:"
            "kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-"
            "AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-"
            "AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!"
            "eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
      } else {
        ciphers =
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:"
            "kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-"
            "AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-"
            "AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-"
            "SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:"
            "CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-"
            "CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
      }

      if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1) {
        // std::cout << "Error setting cipher list" << std::endl;
      }
    }
    catch (std::exception& e) {
      // std::cout << "Exception: " << e.what() << std::endl;
    }
    return ctx;
  }
  FILE* f = fopen("m.txt", "w");
   int name =-1;
  void on_open(connection_hdl hdl)
  {
    client* c = new client();
    c->name = xdm [name++];
    //std::cout  << "someone is connected "<<c->name<<  " "<<m_connections.size()<<std::endl;
    //cout  << "c is "<<c->first <<std::endl;
    c->serverx = &m_server;
    connected_clients.push_back(c);
    c->handle = &hdl;
    m_connections.insert(hdl);
  }

  void on_close(connection_hdl hdl)
  {
        con_list::iterator id = m_connections.find(hdl);

        client* c = connected_clients.at(std::distance(m_connections.begin(), id));
        // cout << "o at " <<connected_clients.at(0)->name;
        // c->iserror =true;
        //  free(c);
        // std::cout << "\n--------\n";
        // for (size_t i = 0; i < connection; i++)
        // {
          /* code */
        // }
        
        std::cout << "\n--------\n";
         cout << "removed connection" <<c->name <<endl;
    connected_clients.erase(connected_clients.begin() + std::distance(m_connections.begin(), id));
    m_connections.erase(id);
    std::cout << "current connected clients " << m_connections.size() << std::endl;
  }
  int x = 0;
  FILE* fx = fopen("i.wav", "wb");
  void on_message(connection_hdl hdl, server::message_ptr msg)
  {
    msg->set_opcode(websocketpp::frame::opcode::BINARY);
    con_list::iterator id = m_connections.find(hdl);
    
    client* c = connected_clients.at(std::distance(m_connections.begin(), id));
   // std::cout << "on location " << std::distance(m_connections.begin(), id) <<std::endl;
    
    // std::cout << "at on message"<<c->first<<std::endl;
    if (c->verifyed_tryed == false) {

      // client sended the first message
      c->verifyed_tryed = true;
      json configx;
      
      configx = json::parse(msg->get_payload().c_str());

      c->api_key = configx["api_key"];
      for (auto& elem : configx["language"]) c->language.push_back(elem);
      c->format = configx["format"];
      c->profanity = configx["profanity"];
      c->interim = configx["interim"];
      c->word_time_offset = configx["word_time_offset"];
      c->number_of_streams = configx["number_of_streams"];
      nvidia::riva::AudioEncoding myencoding;
      if(c->format == "LINEAR-PCM"){
        myencoding =nvidia::riva::LINEAR_PCM;
      }
      else if(c->format == "FLAC"){
        myencoding = nvidia::riva::FLAC;
      }

      c->sclient = new StreamingRecognizeClient_darshan(c->grpc_channel, true,false,myencoding, c->data, c->m2);
      


     m_server.send(hdl,"{\"message\": \"initialised\"}",websocketpp::frame::opcode::TEXT);

    } else {
      if (c->first == true) {


        cout << "first is called" << std::endl;
        c->first = false;
        c->sendDatatoAsrServer();

        // sendDatatoclient(hdl);
        std::thread t(&client::sendDatatoclient, c, hdl);
        t.detach();
      }
      
      c->m.lock();

      c->datatowritten.append(msg->get_payload());
      c->m.unlock();
    }
  }

  void run(uint16_t port)
  {
    m_server.listen(port);
    m_server.start_accept();
    m_server.run();
  }
  void close()
  {
    m_server.stop();
    m_server.stop_listening();
  }

 private:
  typedef std::set<connection_hdl, std::owner_less<connection_hdl>> con_list;

  server m_server;
  con_list m_connections;
};

broadcast_server serverx;
std::shared_ptr<std::string> data;

void
signal_handler(int signal_num)
{
  static int count;
  if (count > 0) {
    std::cout << "Force exit\n";
    serverx.close();
    exit(1);
  }
  std::cout << "Stopping capture\n";
  g_request_exit = true;
  count++;
}


int
main()
{
  
  std::signal(SIGINT, signal_handler);

  serverx.run(9002);
}
