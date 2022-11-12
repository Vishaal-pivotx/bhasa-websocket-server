#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <execution>
#include <chrono>
#include <cassert>
#include <thread>
#include "roots.h"
// includes for websocket
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include "boost/certify/https_verification.hpp"

#include "json.hpp"
#include "AudioFile.h"
#include "wav_loader.h"
#define CHUNK_SIZE 5000
#define needread ((16000 * CHUNK_SIZE / 1000) * sizeof(int16_t))

FILE *f;
clock_t start, end;
int w1, w2, w3;
int r;
// gets filename without path and WITH extension
inline std::string baseFileName(const std::string &pathname)
{
    return {std::find_if(pathname.rbegin(), pathname.rend(),
                         [](char c)
                         {
                             return c == '/' || c == '\\';
                         })
                .base(),
            pathname.end()};
}
static int x = 0;
static void usage(const std::string &fn)
{
    std::cout << baseFileName(fn) << " voice.wav" << std::endl;
}

template <class Wss, class What>
static size_t syncWrite(Wss &wss, What &&what)
{
    namespace net = boost::asio;
    auto fw = wss.async_write(std::forward<What>(what), net::use_future);
    return fw.get();
}

int main(const int argc, const char *argv[])
{

    int result = 0;
    using json = nlohmann::json;
    f = fopen("my.bin", "wb");
    if (f == 0)
    {
        perror("error");
    }
    fflush(f);
    // const static std::string bhasaEndpoint = "wss://transcribe-api.bhasa.io/ws/listen";

    // parsed original "endpoint", as connection is couple-steps things

    // 1. we need to resolve IP
    const static std::string ws_host = "127.0.0.1";
    // 2. we need to setup path ("endpoint")
    const static std::string ws_path = "/ws/listen";
    // 3. we use port during IP resolve too, default is 80 or 443 for SSL in browsers
    const static std::string ws_port = "9002";
    // 4. and last but not least we will indicate SSL by using SSL stream objects below ("wss:/" part)

    //{"api_key":"<APIKEY>","event":"config","format":"LINEAR16","language":"en-US","rate":"audio_context.sampleRate"}
    const static json initer =
        {

            {"language", {"en-us", "en-uk"}},
            {"format", "LINEAR16"},
            {"api_key", "rhturjju"},
            {"profanity", true},
            {"interim", true},
            {"word_time_offset", true},
            {"number_of_streams", 2}};

    if (argc < 2)
        usage(argv[0]);
    else
    {
        std::vector<short> samples;
        {
            // WARNING! No checks are made, be sure source file is correct 2 bytes per sample PCM!!
            const auto wav_bytes = wav::load2ram(argv[1]);
            assert(wav_bytes.second.index() == 2); // expecting source test file 16 bits

            const auto &src = std::get<2>(wav_bytes.second);
            if (1 == wav_bytes.first.channels)
                samples = src;
            else
            {
                // still some, if it was stereo - dropping 1 channel
                samples.reserve(src.size() / wav_bytes.first.channels);
                for (size_t off = 0, sz = src.size(); off < sz; off += wav_bytes.first.channels)
                    samples.push_back(src[off]);
            }
        }

        // we're still ok - file was loaded above and we got some samples
        // https://www.boost.org/doc/libs/1_70_0/libs/beast/doc/html/beast/using_websocket.html
        // https://www.boost.org/doc/libs/1_73_0/libs/beast/doc/html/beast/quick_start/websocket_client.html

        if (samples.size() && !result)
        {
            // all this below must be placed on the same thread,
            // samples may come from outside and make sure it will be synced to this thread

            namespace beast = boost::beast;         // from <boost/beast.hpp>
            namespace http = beast::http;           // from <boost/beast/http.hpp>
            namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
            namespace net = boost::asio;            // from <boost/asio.hpp>
            namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>

            using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

            // The io_context is required for all I/O
            net::io_context ioc;

            // The SSL context is required, and holds certificates
            ssl::context ctx{ssl::context::tlsv13_client};
            load_root_certificates(ctx);
            // verify SSL context (that code uses "certify" lib bounded to example)
            ctx.set_verify_mode(boost::asio::ssl::verify_none);
            // ctx.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);
            ctx.set_default_verify_paths();
            boost::certify::enable_native_https_server_verification(ctx);

            // These objects perform our I/O
            websocket::stream<beast::ssl_stream<tcp::socket>> wss(net::make_strand(ioc), ctx);

            // amount of samples sent to server per write
            constexpr static size_t write_fragment = 4096;

            // callbacks for async_*** use own thread again, so variables outside lambdas/callbacks
            // should be thread - safe

            constexpr size_t bytes_per_sample = sizeof(decltype(samples)::value_type);

            // ATTENTION!! But works for now as is
            // try this: https://www.boost.org/doc/libs/1_67_0/libs/beast/doc/html/beast/using_websocket/send_and_receive_messages.html
            // lowest level write

            std::atomic<size_t> offset(0); // samples (not bytes!)
            FILE *r = fopen("i_phone.wav", "rb");
            FILE *rcv = fopen("m.wav","wb");
            const auto current_write = [&offset, &samples,r,rcv]()
            {

                char m[needread + 1];
                size_t x = fread(m, 1, needread, r);

                 fwrite(m, 1, x, rcv);
                // std::cerr << "Next  = " << offset << std::endl;
                return net::buffer(m,x);
            };

            // declaring explicit type instead auto so lambda can capture itself and use recursive
            using rw_t = std::function<void(beast::error_code, std::size_t)>;

            beast::flat_buffer buffer;
            std::shared_ptr<std::mutex> m=std::make_shared<std::mutex>();
            const rw_t recursion_read = [&](auto ec, auto readed)
            {
                // r += 1;
                //  std::cout << "reading" << std::endl;
                // I don't clear buffer (it has 3 methods - clear what was read, what was written and all)
                // so at the end it will have full text collected,  but this cout will show progress
                // std::cout << beast::make_printable(buffer.data()) << std::endl;
                //  end = clock();
                // std::cout << "\n r is "<<readed<<" time is " <<(double)(end-start)/CLOCKS_PER_SEC<<std::endl;
                 m->lock();
                 std::cout << beast::make_printable(buffer.data());
                 std::cout.flush();
                 buffer.clear();
                 m->unlock();
                if (!ec)
                {
                    wss.async_read(buffer, recursion_read);
                }
            };

            auto stop_check = std::chrono::system_clock::now();
            const rw_t recursion_write = [&](auto, auto written /*bytes*/) {
             
                
                    if (!feof(r)) wss.async_write(current_write(), recursion_write);
                    else std::cout << "exiting"<<std::endl;
                   
                
            };

            const auto async_rw = [&](auto)
            {
                // std::cerr << "on rw\n";
                // Send the message

                try
                {
                    wss.text(true);
                    wss.write(net::buffer(initer.dump()));
                    // std::cerr << "Wrote JSON." << std::endl;
                }
                catch (std::exception &ec)
                {

                    std::cout << ec.what() << std::endl;
                }

                wss.binary(true);
                wss.auto_fragment(true);
                wss.write_buffer_bytes(write_fragment * bytes_per_sample);

                // launching recursion initially
                //  std::cout << "writing recursive";
                // fwrite(current_write().data(), 1, current_write().size(), f);

                // writing sncronized data

                // char mn/[79];
                // fread(mn, 1, 78, r);

                std::cout << "writing" << std::endl;

                
                // wss.write_some(true, boost::asio::buffer(m, x));

                // x = fread(m, 1, needread, r);
                // wss.write_some(true, boost::asio::buffer(m, x));

                std::cout << "over" << std::endl;
                wss.async_write(current_write(), recursion_write);
                start = clock();
                std::cout << "reading" << std::endl;
                wss.async_read(buffer, recursion_read);
                // std::cout << "start reading"<<std::endl;
            };

            const auto on_ssl_handshake = [&wss, async_rw](auto)
            {
                // std::cerr << "on ssl handshake\n";
                // Set a decorator to change the User-Agent of the handshake
                wss.set_option(websocket::stream_base::decorator([](websocket::request_type &req)
                                                                 { req.set(http::field::user_agent,
                                                                           std::string(BOOST_BEAST_VERSION_STRING) +
                                                                               " websocket-transcript-cpp-example"); }));

                // Set suggested timeout settings for the websocket
                wss.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
                wss.async_handshake(ws_host, ws_path, async_rw);
            };

            const auto on_connect = [&wss, &on_ssl_handshake](auto)
            {
                // std::cerr << "on connect\n";
                // Set SNI Hostname (many hosts need this to handshake successfully)
                if (!SSL_set_tlsext_host_name(wss.next_layer().native_handle(), ws_host.c_str()))
                    throw beast::system_error(beast::error_code(static_cast<int>(::ERR_get_error()),
                                                                net::error::get_ssl_category()),
                                              "Failed to set SNI Hostname");

                // 1.2 Perform the SSL handshake
                wss.next_layer().async_handshake(ssl::stream_base::client, on_ssl_handshake);
            };

            // actual starting code
            boost::asio::ip::tcp::resolver resolver(ioc);
            boost::asio::ip::tcp::resolver::query resolver_query(ws_host, ws_port,
                                                                 boost::asio::ip::tcp::resolver::query::numeric_service);
            const auto rr = resolver.resolve(ws_host, ws_port);
            const boost::asio::ip::tcp::endpoint endpoint(*rr);
            // ready to go, once ioc.run(); executed chain of callbacks will go upward from here
            beast::get_lowest_layer(wss).async_connect(endpoint, on_connect);

            // launching possibility to use async_*** functions (event loop)
            // real read/write happens when callback exits, so can't use deep loops there, must be fast
            ioc.run();

            std::cout << std::endl
                      << std::endl
                      << "FINAL: " << beast::make_printable(buffer.data()) << std::endl;
            std::cout << std ::endl
                      << w1 << "  " << w2;
        }
    }
    return result;
}
