#pragma once
#include <mutex>

#include "../utils/grpc.h"
#include "streaming_recognize_client.h"

namespace nr = nvidia::riva;
namespace nr_asr = nvidia::riva::asr;
using namespace std::chrono_literals;
class client {
 public:
  client()
  {
    std::shared_ptr<grpc::ChannelCredentials> creds;

    creds = grpc::InsecureChannelCredentials();
    grpc_channel = riva::clients::CreateChannelBlocking("216.48.182.2:50051", creds);
    
  }
  bool verified = false;
  bool verifyed_tryed = false;
  std::string api_key;
  std::vector<std::string> language;
  std::string format;
  bool profanity;
  bool interim;
  bool word_time_offset;
  int number_of_streams;
  bool auth = false;
  websocketpp::connection_hdl* handle;
  bool jobcompleted = false;
  bool first = false;
  std::string datatowritten;
  StreamingRecognizeClient_darshan* sclient;
  std::mutex m;
  std::shared_ptr<std::mutex> m2 = std::make_shared<std::mutex>();
  std::shared_ptr<std::string> data = std::make_shared<std::string>(std::string());

  websocketpp::server<websocketpp::config::asio_tls>  *serverx;
  void sendDatatoAsrServer()
  {
    // std::cout << "sending data to asr server" << std::endl;
    //   sclient->sendData(datatowritten);
    // (*data)->append("hheekkek");
    std::thread t(&client::datasendfunction, this);

     

    
    t.detach();



    // serverx->send(&handle,"hello",)
  }
  std::shared_ptr<grpc::Channel> grpc_channel;

  void sendDatatoclient(connection_hdl hdl){
        while (1)
        {
            // cout << "e"<<data->length() << std::endl;
            mx2.lock();
             if(data->length() !=0){
            //   std::cout << "sending data to client"<<std::endl;
              std::error_code ec;
              m2->lock();
              std::cout << "\n sending data to the servver" <<std::endl;
              std::cout << *data.get();
              serverx->send(hdl,*data.get(),websocketpp::frame::opcode::TEXT,ec);

              data->clear();
                            std::cout << "\n sending data to the servver over"<<std::endl;

              m2->unlock();
                // cout << "\n "<<ec.message();
               // exit(0);
           }
           else{
            // std::cout << "empty"<<std::endl;
           }
           mx2.unlock();
        }
        
    }

  void datasendfunction()
  {
    
    while (jobcompleted != true) {
     // std::cout << "ow\n"<<std::endl;
     
      while (!datatowritten.empty()) {
        // std::cout << "ow 2\n"<<std::endl;
        m.lock();


        // std::cout << "sending data" << std::endl;
        size_t z = sclient->sendData(datatowritten);

        datatowritten.erase(datatowritten.begin(), datatowritten.begin() + z);
        m.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
          //std::cout << "data sended"<<std::endl;
             
    }
  }
};
