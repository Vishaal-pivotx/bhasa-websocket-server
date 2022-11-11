#pragma once
#include"streaming_recognize_client.h"
#include"../utils/grpc.h"
#include <mutex>
namespace nr = nvidia::riva;
namespace nr_asr = nvidia::riva::asr;
using namespace std::chrono_literals;
class client
{
public:
    client()
    {

         std::shared_ptr<grpc::ChannelCredentials> creds;
     
        creds = grpc::InsecureChannelCredentials();
         grpc_channel =   riva::clients::CreateChannelBlocking("216.48.182.2:50051", creds);

         
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
    websocketpp::connection_hdl *handle;
    bool jobcompleted = false;
    std::string datatowritten;
    StreamingRecognizeClient_darshan *sclient;
    std::mutex m;
    void sendDatatoAsrServer()
    {

                  sclient->sendData(datatowritten);

        
    }
    std::shared_ptr<grpc::Channel> grpc_channel;

    void sendDataToclient()
    {
    }

};
