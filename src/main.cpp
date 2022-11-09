
#include <iostream>
#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>
#include "client.h"
#include <nlohmann/json.hpp>
#include <memory>

typedef websocketpp::server<websocketpp::config::asio_tls> server;

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using json = nlohmann::json;
using namespace std;
std::vector<std::string> acceptable_keys = {"eaaassdr", "yfnhjfgt", "rhturjju"};
std::vector<client> connected_clients;

// pull out the type of messages sent by our config
typedef websocketpp::config::asio::message_type::ptr message_ptr;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
bool x = 0;
int xi = 0;
bool verify = false;
bool auth = true;
void on_message(server *s, websocketpp::connection_hdl hdl, message_ptr msg)
{

    hdl.lock().get();

    if (verify == false)
    {

        json configx;
        std::cout << "init json " << std::endl;
        configx = json::parse(msg->get_payload().c_str());

        string api_key = configx["api_key"];
        std::vector<std::string> language;

        for (auto &elem : configx["language"])
            language.push_back(elem);
        string format = configx["format"];

        bool profanity = configx["profanity"];
        bool interim = configx["interim"];
        bool word_time_offset = configx["word_time_offset"];
        int number_of_streams = configx["number_of_streams"];

        std::cout << "\n---------------\n";
        cout << "API key is " << api_key << endl;
        cout << "format is  " << format << endl;
        cout << "number of stream  is  " << number_of_streams << endl;
        cout << "word time offset is  " << word_time_offset << endl;
        cout << "interim is  " << interim << endl;
        cout << "profanity is  " << profanity << endl;
        cout << "language is  " << language.at(0) << endl;

        std::cout << "---------------\n";
        for (std::string s : acceptable_keys)
        {
            if (s.compare(api_key) == 0)
            {
                // std::cout << "authentication successfull"<<std::endl;
                auth = true;
            }
        }
        verify = true;
    }
    else
    {

        // data is coming

        s->send(hdl, " This is dummy text ", websocketpp::frame::opcode::TEXT);
    }
    return;
}

void on_http(server *s, websocketpp::connection_hdl hdl)
{
    server::connection_ptr con = s->get_con_from_hdl(hdl);

    con->set_body("Hello World!");
    con->set_status(websocketpp::http::status_code::ok);
}

std::string get_password()
{
    return "test";
}

enum tls_mode
{
    MOZILLA_INTERMEDIATE = 1,
    MOZILLA_MODERN = 2
};

context_ptr on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl)
{
    namespace asio = websocketpp::lib::asio;

    std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;
    std::cout << "using TLS mode: " << (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate") << std::endl;

    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try
    {
        if (mode == MOZILLA_MODERN)
        {
            // Modern disables TLSv1
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::single_dh_use);
        }
        else
        {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::single_dh_use);
        }
        ctx->set_password_callback(bind(&get_password));
        ctx->use_certificate_chain_file("server.pem");
        ctx->use_private_key_file("server.pem", asio::ssl::context::pem);

        // Example method of generating this file:
        // `openssl dhparam -out dh.pem 2048`
        // Mozilla Intermediate suggests 1024 as the minimum size to use
        // Mozilla Modern suggests 2048 as the minimum size to use.
        ctx->use_tmp_dh_file("dh.pem");

        std::string ciphers;

        if (mode == MOZILLA_MODERN)
        {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
        }
        else
        {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
        }

        if (SSL_CTX_set_cipher_list(ctx->native_handle(), ciphers.c_str()) != 1)
        {
            std::cout << "Error setting cipher list" << std::endl;
        }
    }
    catch (std::exception &e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    return ctx;
}

int main()
{
    // Create a server endpoint
    server Mainserver;

    Mainserver.set_access_channels(websocketpp::log::alevel::none);
    // Initialize ASIO
    Mainserver.init_asio();

    // Register our message handler
    Mainserver.set_message_handler(bind(&on_message, &Mainserver, ::_1, ::_2));
    Mainserver.set_http_handler(bind(&on_http, &Mainserver, ::_1));
    Mainserver.set_tls_init_handler(bind(&on_tls_init, MOZILLA_INTERMEDIATE, ::_1));

    // Listen on port 9002
    Mainserver.listen(9002);

    // Start the server accept loop
    Mainserver.start_accept();

    // Start the ASIO io_service run loop
    Mainserver.run();
}
