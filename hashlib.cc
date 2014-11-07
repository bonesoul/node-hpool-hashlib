// 
//     hpool-hashlib - hashing library for hpool
//     Copyright (C) 2013 - 2014, hpool project 
//     http://www.hpool.org - https://github.com/int6/hpool-stratum
// 
//     This software is dual-licensed: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
// 
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//    
//     For the terms of this license, see licenses/gpl_v3.txt.
// 
//     Alternatively, you can license this software under a commercial
//     license or white-label it as set out in licenses/commercial.txt.
//

#include <node.h>
#include <node_buffer.h>
#include <v8.h>

extern "C" {
#include "scryptn.h"
}

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
	return ThrowException(Exception::Error(String::New(msg)));
}

Handle<Value> scrypt(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 3)
		return except("You must provide buffer to hash, N value, and R value");

	Local<Object> target = args[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return except("Argument should be a buffer object.");

	Local<Number> numn = args[1]->ToNumber();
	unsigned int nValue = numn->Value();
	Local<Number> numr = args[2]->ToNumber();
	unsigned int rValue = numr->Value();

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

	Buffer* buff = Buffer::New(output, 32);
	return scope.Close(buff->handle_);
}

Handle<Value> scryptn(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 2)
		return except("You must provide buffer to hash and N factor.");

	Local<Object> target = args[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return except("Argument should be a buffer object.");

	Local<Number> num = args[1]->ToNumber();
	unsigned int nFactor = num->Value();

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	//unsigned int N = 1 << (getNfactor(input) + 1);
	unsigned int N = 1 << nFactor;

	scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


	Buffer* buff = Buffer::New(output, 32);
	return scope.Close(buff->handle_);
}

void init(Handle<Object> exports) {
	exports->Set(String::NewSymbol("scrypt"), FunctionTemplate::New(scrypt)->GetFunction());
	exports->Set(String::NewSymbol("scryptn"), FunctionTemplate::New(scryptn)->GetFunction());
}

NODE_MODULE(hashlib, init)