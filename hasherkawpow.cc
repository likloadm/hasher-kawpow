#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <iostream>
#include "nan.h"
#include "include/ethash.h"
#include "include/ethash.hpp"
#include "include/progpow.hpp"
#include "uint256.h"
#include "helpers.hpp"

using namespace node;
using namespace v8;

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}


NAN_METHOD(hash_one) {
        if (info.Length() < 3)
            return THROW_ERROR_EXCEPTION("hasher-kawpow.hash_one - 3 arguments expected.");

        const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
        uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
        int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
        ethash::hash256* mix_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
        ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

        static ethash::epoch_context_ptr context{nullptr, nullptr};

        const auto epoch_number = ethash::get_epoch_number(block_height);

        if (!context || context->epoch_number != epoch_number)
            context = ethash::create_epoch_context(epoch_number);

        progpow::hash_one(*context, block_height, header_hash_ptr, *nonce64_ptr, mix_out_ptr, hash_out_ptr);
}


NAN_METHOD(verify) {
        if (info.Length() < 5)
            return THROW_ERROR_EXCEPTION("hasher-kawpow.verify - 5 arguments expected.");

        const ethash::hash256* header_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[0]).ToLocalChecked());
        uint64_t* nonce64_ptr = (uint64_t*)Buffer::Data(Nan::To<v8::Object>(info[1]).ToLocalChecked());
        int block_height = info[2]->IntegerValue(Nan::GetCurrentContext()).FromJust();
        const ethash::hash256* mix_hash_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[3]).ToLocalChecked());
        ethash::hash256* hash_out_ptr = (ethash::hash256*)Buffer::Data(Nan::To<v8::Object>(info[4]).ToLocalChecked());

        static ethash::epoch_context_ptr context{nullptr, nullptr};

        const auto epoch_number = ethash::get_epoch_number(block_height);

        if (!context || context->epoch_number != epoch_number)
            context = ethash::create_epoch_context(epoch_number);

        bool is_valid = progpow::verify(*context, block_height, header_hash_ptr, *mix_hash_ptr, *nonce64_ptr, hash_out_ptr);

        if (is_valid) {
           info.GetReturnValue().Set(Nan::True());
        }
        else {
           info.GetReturnValue().Set(Nan::False());
        }
}

NAN_METHOD(light_verify) {
        if (info.Length() < 5)
            return THROW_ERROR_EXCEPTION("hasher-kawpow.light_verify - 5 arguments expected.");
        Local<Function> cb = Local<Function>::Cast(info[0]);
        String::Utf8Value str(info[0]);
        const char* header_hash_ptr = ToCString(str);

        Local<Function> cb1 = Local<Function>::Cast(info[1]);
        String::Utf8Value str1(info[1]);
        const char* mix_out_ptr = ToCString(str1);

        Local<Function> cb2 = Local<Function>::Cast(info[2]);
        String::Utf8Value str2(info[2]);
        const char* nonce64_ptr = ToCString(str2);

        int block_height = info[3]->IntegerValue(Nan::GetCurrentContext()).FromJust();

        Local<Function> cb4 = Local<Function>::Cast(info[4]);
        String::Utf8Value str4(info[4]);
        const char* share_boundary_str = ToCString(str4);

        Local<Function> cb5 = Local<Function>::Cast(info[5]);
        String::Utf8Value str5(info[5]);
        const char* block_boundary_str = ToCString(str5);

         Local<Function> cb3 = Local<Function>::Cast(info[3]);
        String::Utf8Value str3(info[3]);
        const char* block_height_str = ToCString(str3);


        static ethash::epoch_context_ptr context{nullptr, nullptr};

        const auto epoch_number = ethash::get_epoch_number(block_height);

        bool share_met = false;
        bool block_met = false;
        bool mix_match = false;

        if (!context || context->epoch_number != epoch_number)
            context = ethash::create_epoch_context(epoch_number);

        progpow::light_verify(*context, header_hash_ptr,
                                              mix_out_ptr, nonce64_ptr, block_height_str,
                                              share_boundary_str, block_boundary_str,
                                              share_met, block_met, mix_match);
        bool ResultData[3];
        ResultData[0] = share_met;
        ResultData[1] = block_met;
        ResultData[2] = mix_match;

        Nan::Local<Array> arr = Array::New();
        arr->Set(0, Boolean::New(share_met));
        arr->Set(1, Boolean::New(block_met));
        arr->Set(2, Boolean::New(mix_match));

        info.GetReturnValue().Set(arr);
}

NAN_MODULE_INIT(init) {
        Nan::Set(target, Nan::New("hash_one").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(hash_one)).ToLocalChecked());
        Nan::Set(target, Nan::New("verify").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(verify)).ToLocalChecked());
        Nan::Set(target, Nan::New("light_verify").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(light_verify)).ToLocalChecked());
}

NODE_MODULE(hashermtp, init)