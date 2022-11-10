#pragma once
#include"streaming_recognize_client.h"
#include"../utils/grpc.h"
namespace nr = nvidia::riva;
namespace nr_asr = nvidia::riva::asr;

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
    void sendDatatoAsrServer()
    {
        while (jobcompleted != true)
        {
            while (datatowritten.length() > 0)
            {
   //             std::vector<std::shared_ptr<WaveData>> all_wav;
     //           LoadWavDatax(all_wav);

       //         std::unique_ptr<Stream> stream(new Stream(all_wav.at(0), 1));
         //       StartNewStream(std::move(stream));
                  sclient->sendData(datatowritten);
                  
            }
        }
    }
    std::shared_ptr<grpc::Channel> grpc_channel;

    void sendDataToclient()
    {
    }

    void
    LoadWavDatax(std::vector<std::shared_ptr<WaveData>> &all_wav)
    {
        nr::AudioEncoding encoding;
        int samplerate;
        int channels;
        long data_offset;
        std::shared_ptr<WaveData> wav_data = std::make_shared<WaveData>();

        wav_data->sample_rate = samplerate;
        wav_data->filename = "";
        wav_data->encoding = encoding;
        wav_data->channels = channels;
        wav_data->data_offset = data_offset;
        for (size_t i = 0; i < datatowritten.length(); i++)
        {
            wav_data->data.push_back(datatowritten.at(i));
        }

        all_wav.push_back(std::move(wav_data));
    }
};
