// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array_buffer.h"
#include "ppapi/cpp/var_dictionary.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <ctime>
#include <string>
extern "C" {
#include "openssl_aes.h"
}

class HelloTutorialInstance : public pp::Instance {
 public:
  explicit HelloTutorialInstance(PP_Instance instance)
      : pp::Instance(instance) {}
  virtual ~HelloTutorialInstance() {}

  virtual void HandleMessage(const pp::Var& var_message) {
    // Ignore the message if it is not a string.
    if (!var_message.is_dictionary()) {
      //fprintf(stderr, "Unexpected message.\n");
      return;
    }

    pp::VarDictionary dict_message(var_message);
    pp::Var var_command = dict_message.Get("Cmd");
    if (!var_command.is_string()) {
      //fprintf(stderr, "Expect dict item \"command\" to be a string.\n");
      return;
    }
    std::string command = var_command.AsString();

    // Get the string message and do the encryption.
    if (command == "Encryption"){
      pp::Var var_content = dict_message.Get("Content");
      std::string content = var_content.AsString();

      pp::Var var_NS = dict_message.Get("nReceipt");
      int NS = var_NS.AsInt();

      pp::Var var_fo = dict_message.Get("fo");
      int fo = var_fo.AsInt();

      pp::Var var_p_keys = dict_message.Get("RSA_List");
      pp::VarDictionary dict_keys(var_p_keys);

      //fprintf(stderr, "NS = %d\n", NS);
      char* rsa_keys[NS];

      for (int i=0; i < NS; i++){
        char* i_rsa = (char*) malloc(10);
        sprintf(i_rsa, "%d_rsa", i);

        pp::Var var_rsa = dict_keys.Get(i_rsa);
        std::string rsa_str = var_rsa.AsString();
        rsa_keys[i] = (char*) malloc(rsa_str.length()+1);
        strcpy(rsa_keys[i], (char*)rsa_str.c_str());
      }

      char* rsa_cipher[NS];
      unsigned char* aes_cipher;
      int len_cipher;
      do_encryption((char*) content.c_str(), &aes_cipher, &len_cipher,rsa_keys, rsa_cipher, NS);

      for (int i=0; i < len_cipher; i++)
        fprintf(stderr, "%d-", aes_cipher[i]);
      fprintf(stderr, "\n");

      pp::VarArrayBuffer return_buffer(len_cipher);
      void* return_cipher = return_buffer.Map();
      memcpy(return_cipher, aes_cipher, len_cipher);
      return_buffer.Unmap();

      pp::VarDictionary vReply;
      for (int i=0; i < NS; i++){
          char* key = (char*) malloc(10);
          sprintf(key, "%d", i);
          vReply.Set(key, rsa_cipher[i]);
      }

      vReply.Set("event", "encryption");
      vReply.Set("aes_cipher", return_buffer);
      vReply.Set("NS", NS);
      vReply.Set("fo", fo);
      PostMessage(vReply);
    }
    else if (command == "Decryption"){
      pp::Var var_content = dict_message.Get("Content");
      pp::VarArrayBuffer buffer2(var_content);
      unsigned char* content = static_cast<unsigned char*>(buffer2.Map());
      int len = buffer2.ByteLength();

      pp::Var var_s_keys = dict_message.Get("rsa_skey");
      std::string  _rsa_skey = var_s_keys.AsString();
      char* rsa_skey = (char*)_rsa_skey.c_str();

      pp::Var var_aes_k = dict_message.Get("k");
      std::string  _aes_k = var_aes_k.AsString();
      char* aes_k = (char*)_aes_k.c_str();
      fprintf(stderr, "k %s\n", aes_k);
      fprintf(stderr, "rsa_skey %s\n", rsa_skey);

      char* raw_main;

      do_decryption(content, len, rsa_skey, aes_k, &raw_main);
      pp::VarDictionary vReply;
        vReply.Set("main", raw_main);
        vReply.Set("event", "decryption");
      PostMessage(vReply);
    }

    if (command == "Revocation"){
      pp::Var var_content = dict_message.Get("Diff");
      std::string content = var_content.AsString();


      pp::Var var_NS = dict_message.Get("NS");
      int NS = var_NS.AsInt();

      //fprintf(stderr, "NS = %d\n", NS);
      char* rsa_keys[NS];

      for (int i=0; i < NS; i++){
        char* i_rsa = (char*) malloc(10);
        sprintf(i_rsa, "%d_rsa", i);

        pp::Var var_rsa = dict_message.Get(i_rsa);
        std::string rsa_str = var_rsa.AsString();
        rsa_keys[i] = (char*) malloc(rsa_str.length()+1);
        strcpy(rsa_keys[i], (char*)rsa_str.c_str());
        //fprintf(stderr, "%d-RSA %s\n", i, rsa_keys[i]);
      }

      char* rsa_cipher[NS];
      char* aes_cipher;
      do_revocation((char*) content.c_str(), &aes_cipher, rsa_keys, rsa_cipher, NS);

      pp::VarDictionary vReply;
      for (int i=0; i < NS; i++){
        char* i_id = (char*) malloc(10);
        sprintf(i_id, "%d_id", i);

        char* key = (char*) malloc(10);
        sprintf(key, "%d_key", i);

        pp::Var var_id = dict_message.Get(i_id);
        std::string id_str = var_id.AsString();

        vReply.Set(key, rsa_cipher[i]);
        vReply.Set(i_id, id_str);
      }
      vReply.Set("aes_cipher", aes_cipher);
      vReply.Set("event", "revocation");
      vReply.Set("NS", NS);
      PostMessage(vReply);
    }
  }
};

class HelloTutorialModule : public pp::Module {
 public:
  HelloTutorialModule() : pp::Module() {}
  virtual ~HelloTutorialModule() {}

  virtual pp::Instance* CreateInstance(PP_Instance instance) {
    return new HelloTutorialInstance(instance);
  }
};

namespace pp {

Module* CreateModule() {
  return new HelloTutorialModule();
}

}  // namespace pp
