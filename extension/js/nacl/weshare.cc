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
#include "base64.h"
extern "C" {
  #include "weshare_main.h"
  #include "gettime.h"
}

class HelloTutorialInstance : public pp::Instance {
 public:
  explicit HelloTutorialInstance(PP_Instance instance)
      : pp::Instance(instance) {}
  virtual ~HelloTutorialInstance() {}

  virtual void HandleMessage(const pp::Var& var_message) {
    // Ignore the message if it is not a dict.
    if (!var_message.is_dictionary()) {
      fprintf(stderr, "Unexpected message.\n");
      return;
    }
    start_t();

    pp::VarDictionary dict_message(var_message);
    pp::Var var_command = dict_message.Get("Cmd");
    if (!var_command.is_string()) {
      fprintf(stderr, "Expect dict item \"command\" to be a string.\n");
      return;
    }

    // Get the user and do the setup.
    // message[Cmd] = Setup
    // message[Fo] = file owner
    // message[Keys] = list of all the recipients who hasn't got their di
    //        messa[Keys]['%d_id'] = id of the recipient
    //        messa[Keys]['%d_rsa'] = rsa public key of that recipient
    // message[Keys][new_shared] = number of such recipients
    std::string command = var_command.AsString();
    if (command == "Setup"){
      pp::Var var_fo = dict_message.Get("Fo");
      int fo = var_fo.AsInt();

      pp::Var var_p_keys = dict_message.Get("Keys");
      pp::VarDictionary dict_keys(var_p_keys);

      pp::Var var_p_headers = dict_message.Get("Headers");
      pp::VarArrayBuffer buffer(var_p_headers);
      uint32_t buffer_size = buffer.ByteLength();
      if (buffer_size == 0)
        return;
      unsigned char* headers = static_cast<unsigned char*>(buffer.Map());

      pp::Var var_NS = dict_keys.Get("new_shared");
      int NS = var_NS.AsInt();

      //reading the new recipients who haven't got their shared g_i^gamma \mul g^z
      char* rsa_new_recips[NS];
      int id_new_recip[NS];
      pp::VarDictionary vReply;
      for (int i=0; i < NS; i++){
        char* i_rsa = (char*) malloc(10);
        sprintf(i_rsa, "%d_rsa", i);
        pp::Var var_rsa = dict_keys.Get(i_rsa);
        std::string rsa_str = var_rsa.AsString();
        rsa_new_recips[i] = strdup((char*)rsa_str.c_str());
        // fprintf(stderr, "%d_rsa %s\n", i, rsa_new_recips[i]);

        char* i_id = (char*) malloc(10);
        sprintf(i_id, "%d_id", i);
        pp::Var var_id = dict_keys.Get(i_id);
        id_new_recip[i] = var_id.AsInt();
        // fprintf(stderr, "%s %d\n", i_id, id_new_recip[i]);
        vReply.Set(i_id, id_new_recip[i]);
      }

      char* di[NS];
      do_setup(di, rsa_new_recips, id_new_recip, NS, headers);

      for (int i=0; i < NS; i++){
          char* key = (char*) malloc(10);
          sprintf(key, "%d_di", i);
          vReply.Set(key, di[i]);
      }

      vReply.Set("event", "setup");
      vReply.Set("Fo", fo);
      PostMessage(vReply);
    }
    // Get the string message and do the encryption.
    // message[Cmd] = Encryption
    // message[Content] = the message you want to encrypt
    // message[Fo] = file owner
    // message[Keys] = list of all the recipients who hasn't got their di
    //        messa[Keys]['%d_id'] = id of the recipient
    //        messa[Keys]['%d_rsa'] = rsa public key of that recipient
    // message[Keys][n_shared] = number of such recipients
    else if (command == "Encryption"){
      pp::Var var_content = dict_message.Get("Content");
      std::string content = var_content.AsString();

      pp::Var var_recip = dict_message.Get("Recipients");
      int n_shared = var_recip.AsInt();

      pp::Var var_fo = dict_message.Get("Fo");
      int fo = var_fo.AsInt();
      fprintf(stderr, "Fo = %d\n", fo);

      pp::Var var_p_keys = dict_message.Get("Keys");
      pp::VarDictionary dict_keys(var_p_keys);

      pp::Var var_p_headers = dict_message.Get("Headers");
      pp::VarArrayBuffer buffer(var_p_headers);
      uint32_t buffer_size = buffer.ByteLength();
      if (buffer_size == 0)
        return;
      unsigned char* headers = static_cast<unsigned char*>(buffer.Map());

      pp::VarDictionary vReply;
      unsigned char* main_cipher;
      char* product, *t;
      int len_cipher;
      cipher_pair cp = (cipher_pair) malloc(sizeof(struct ciphertext));
      unsigned char* k1;

      do_encryption(&main_cipher, &len_cipher, cp, &product, &t, (char*) content.c_str(), n_shared, headers, &k1);

      //20 byte is the size of SHA1 output
      char* ret_k1 = base64Encode(k1, 20);

      pp::VarArrayBuffer return_buffer(len_cipher);
      void* return_cipher = return_buffer.Map();
      memcpy(return_cipher, main_cipher, len_cipher);
      return_buffer.Unmap();


      vReply.Set("event", "encryption");
      vReply.Set("main_cipher", return_buffer);
      vReply.Set("C0", cp->C0);
      vReply.Set("C1", cp->C1);
      vReply.Set("Fo", fo);
      vReply.Set("n_shared", n_shared);
      vReply.Set("product", product);
      vReply.Set("t", t);
      vReply.Set("k1", ret_k1);
      PostMessage(vReply);
    }
    // Get the ciphertext and do the decryption.
    // message[Cmd] = decryption
    // message[Content] = the ciphertext you want to decrypt
    // message[Headers] = the gbs parameters
    // message[index] = index of the downloader
    // message[di] = the di shared by the fo
    // message[n_shared] = number of current recipients
    // message[C0, C1] = ciphertext params...
    else if (command == "Decryption"){
      pp::Var var_content = dict_message.Get("Content");
      pp::VarArrayBuffer buffer2(var_content);
      unsigned char* ciphertext = static_cast<unsigned char*>(buffer2.Map());
      int len = buffer2.ByteLength();

      pp::Var var_p_headers = dict_message.Get("Headers");
      pp::VarArrayBuffer buffer(var_p_headers);
      unsigned char* headers = static_cast<unsigned char*>(buffer.Map());


      pp::Var var_NS = dict_message.Get("n_shared");
      int NS = var_NS.AsInt();

      pp::Var var_ONS = dict_message.Get("o_n_shared");
      int ONS = var_ONS.AsInt();

      pp::Var var_id = dict_message.Get("index");
      int id = var_id.AsInt();

      pp::Var var_C0 = dict_message.Get("C0");
      std::string C0 = var_C0.AsString();

      pp::Var var_C1 = dict_message.Get("C1");
      std::string C1 = var_C1.AsString();

      pp::Var var_OC0 = dict_message.Get("OC0");
      std::string OC0 = var_OC0.AsString();

      pp::Var var_OC1 = dict_message.Get("OC1");
      std::string OC1 = var_OC1.AsString();

      pp::Var var_di = dict_message.Get("di");
      std::string di = var_di.AsString();

      char* plaintext;
      do_decryption (&plaintext, headers,
        ciphertext, len, (char*) C0.c_str(),
        (char*) C1.c_str(), (char*) OC0.c_str(),
        (char*) OC1.c_str(), (char*) di.c_str(), id, NS, ONS);

      pp::VarDictionary vReply;
      vReply.Set("event", "decryption");
      vReply.Set("plaintext", plaintext);

      PostMessage(vReply);
    }
    // Revoke some recipients
    // message[Cmd] = Revocation
    // message[Content] = the ciphertext you want to decrypt
    // message[Headers] = the gbs parameters
    // message[n_shared] = number of current recipients
    // message[n_revoked] = number of revoked users, after that n_share -= n_revoked
    // message[C0, C1] = ciphertext params...
    // message[product]: the product of recipients
    else if (command == "Revocation"){
      pp::Var var_p_headers = dict_message.Get("Headers");
      pp::VarArrayBuffer buffer(var_p_headers);
      unsigned char* headers = static_cast<unsigned char*>(buffer.Map());

      pp::Var var_NS = dict_message.Get("n_shared");
      int NS = var_NS.AsInt();

      //will revoke n_revoked users..
      pp::Var var_n_revoked = dict_message.Get("n_revoked");
      int n_revoked = var_n_revoked.AsInt();

      pp::Var var_C0 = dict_message.Get("C0");
      std::string C0 = var_C0.AsString();

      pp::Var var_C1 = dict_message.Get("C1");
      std::string C1 = var_C1.AsString();

      pp::Var var_prod = dict_message.Get("product");
      std::string product = var_prod.AsString();

      char* new_prod, *new_t;
      unsigned char* k1;

      cipher_pair new_cp = (cipher_pair) malloc(sizeof(struct ciphertext));
      do_revocation (headers, (char*) product.c_str(), NS, n_revoked, new_cp,
        &new_prod, &new_t, &k1);

      //20 byte is the size of SHA1 output
      char* ret_k1 = base64Encode(k1, 20);

      pp::VarDictionary vReply;
      vReply.Set("event", "revocation");
      vReply.Set("k1", ret_k1);
      vReply.Set("C0", new_cp->C0);
      vReply.Set("C1", new_cp->C1);
      vReply.Set("t", new_t);
      vReply.Set("n_shared", NS-n_revoked);
      vReply.Set("product", new_prod);
      PostMessage(vReply);
    }

    // Share to more users
    // message[Cmd] = share
    // message[Headers] = the gbs parameters
    // message[n_shared] = number of current recipients
    // message[n_new] = number of new shared users, after that n_share += n_revoked
    // message[C0, C1] = ciphertext params...
    // message[product]: the product of current recipients
    // message[t]: the current t
    else if (command == "Sharing"){
      pp::Var var_p_headers = dict_message.Get("Headers");
      pp::VarArrayBuffer buffer(var_p_headers);
      unsigned char* headers = static_cast<unsigned char*>(buffer.Map());

      pp::Var var_NS = dict_message.Get("n_shared");
      int NS = var_NS.AsInt();

      pp::Var var_new = dict_message.Get("n_new");
      int n_new = var_new.AsInt();

      pp::Var var_t = dict_message.Get("t");
      std::string t = var_t.AsString();

      pp::Var var_prod = dict_message.Get("product");
      std::string product = var_prod.AsString();

      char* new_prod, *new_C1;

      do_sharing(headers, (char*) product.c_str(), (char*) t.c_str(),
        NS, n_new, &new_prod, &new_C1);

      pp::VarDictionary vReply;
      vReply.Set("event", "sharing");
      vReply.Set("C1", new_C1);
      vReply.Set("n_shared", NS+n_new);
      vReply.Set("product", new_prod);
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
