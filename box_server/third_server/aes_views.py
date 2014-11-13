__author__ = 'loi'
import json
from django.shortcuts import render
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
import requests
from weshare.models import *
from django.core.servers.basehttp import FileWrapper
import random
import subprocess
from Crypto.PublicKey import RSA
import os
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
from views import NUM_USERS


@csrf_exempt
def aes_get_rsa_list(request):
    try:
        i=0
        ret_data = {}
        for id in range(NUM_USERS):
            try:
                user_b = User.objects.get(index=id+1)
                ret_data[str(id)+"_rsa"] = user_b.public_rsa
            except Exception as e:
                raise e
        ret_data['NS'] = NUM_USERS
    except Exception as e:
        print "Errors " + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

def aes_download(request, file_id, user_id):

    try:
        f = AESFiles.objects.get(file_id=file_id)
        u = AESUser.objects.get(box_id=user_id)
        recep =AESRecipient.objects.get(file_id=f, user_id=u)


        ret_data={
            'success': True,
            "rsa_skey": u.secret_rsa,
            "rsa_encrypted_main_k": recep.main_k,
            "rsa_encrypted_diff_k": recep.diff_k
        }
    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def aes_keys_for_revocation(request):
    data = request.POST
    try:
        file_id = data['file_id']
        revoked_ids = data['revoke_set'].split()
        f = AESFiles.objects.get(file_id=file_id)
        fo = f.user_id
        recips = AESRecipient.objects.filter(file_id=f)

        ret_data={
            'success': True,
        }
        i = 0
        print 'revoke set' + str(revoked_ids)
        for receip in recips:
            if not (receip.user_id.box_id in revoked_ids):
                ret_data[str(i)+"_id"]=receip.user_id.box_id
                ret_data[str(i)+"_rsa"]=receip.user_id.public_rsa
                i+=1
        ret_data['NS']=i

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }

    data = json.dumps(ret_data)
    return HttpResponse(data, content_type='application/json')


@csrf_exempt
def aes_complete_revocation(request):
    try:
        data = request.POST
        file_id = data['file_id']
        print "AES revocking file: " + file_id
        #for u, v in data.iteritems():
        #    print u, v
        #    print "\n"
        f = AESFiles.objects.get(file_id = file_id)
        NS = int(data['NS'])
        ret_data={
            'success': True,
        }
        for i in range(NS):
            id = data[str(i)+'_id']
            new_keys = data[str(i)+'_key']
            r = AESUser.objects.get(box_id=id)
            aes_recip = AESRecipient.objects.get(file_id=f, user_id=r)
            aes_recip.diff_k = new_keys
            aes_recip.save()

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': True,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def aes_download_for_editing(request):
    try:
        data = request.POST
        print data
        file_id = data['file_id']
        user_id = data['user_id']
        print "AES request to edit file: " + file_id

        f = AESFiles.objects.get(file_id = file_id)
        u = AESUser.objects.get(box_id=user_id)
        r = AESRecipient.objects.get(file_id=f, user_id=u)
        ret_data={
            'success': True,
            'rsa_skey': u.secret_rsa,
            'diff_k': r.diff_k
        }

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': True,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')


def download_content_from_box(file_id, access_token):
    #16600831793/IwsXugGtipPIKMKODaAnYYmjHRGwmOAp
    url = 'https://api.box.com/2.0/files/' + file_id + '/content'
    auth = 'Bearer ' + access_token
    payload = {
        'crossDomain': True,
        'dataType': 'json',
        'content-type': 'application/json'
    }

    headers = {
        "Authorization": auth
    }
    while True:
        r = requests.get(url, data=json.dumps(payload), headers=headers)
        if len(r.text):
            break

    print "Done download content from box " + str(file_id)
    return str(r.text)

def update_to_box(file_id, filename, access_token):
    url = 'https://upload.box.com/api/2.0/files/'+file_id+'/content'
    auth = 'Bearer ' + access_token
    headers = {
        "Authorization": auth
    }
    f = open(filename, "r")

    r = requests.post(url, headers=headers, files={'file': f})
    print 'update to box done' + str(file_id)


@csrf_exempt
def aes_query_keys(request):
    data = request.POST
    try:
        fo_id = data['fo']
        try:
            aes_user = AESUser.objects.get(box_id=fo_id)
        except Exception as e:
            private = RSA.generate(1024)
            public = private.publickey()
            aes_user = AESUser(box_id=fo_id, public_rsa=public.exportKey(), secret_rsa=private.exportKey())
            aes_user.save()

        receip_ids = data['recipient'].split(" ")
        i=0
        ret_data = {'n_shared': len(receip_ids)}
        for id in receip_ids:
            try:
                aes_user = AESUser.objects.get(box_id=id)
            except Exception as e:
                private = RSA.generate(1024)
                public = private.publickey()
                aes_user = AESUser(box_id=id, public_rsa=public.exportKey(), secret_rsa=private.exportKey())
                aes_user.save()

            ret_data[str(i)+"_rsa"] = aes_user.public_rsa
            i+=1
    except Exception as e:
        print "Errors " + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')


#This is called when user uploads any function
@csrf_exempt
def aes_complete_upload(request):
    try:
        data = request.POST
        print data
        file_id = data['file_id']
        print "AES uploading file: " + file_id

        NS = int(data['NS'])
        fo_id = int(data['fo'])
        try:
            fo = AESUser.objects.get(index=fo_id)
        except Exception as e:
            print "User " + str(fo_id) + " not found" + str(e) + "\n"
            raise e

        new_file = AESFiles(file_id=file_id, user_id=fo, NS=NS)
        new_file.save()

        ret_data={
            'success': True,
        }
        for id in range(NS):
            try:
                r = AESUser.objects.get(index=id+1)
            except Exception as e:
                print "User " + str(id) + " not found" + str(e) + "\n"
                raise e

            new_aes_recip = AESRecipient(file_id=new_file, user_id=r, k=data[str(id)])
            new_aes_recip.save()
            ret_data[id] = True

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': True,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')


def aes_download(request, file_id, user_id):
    try:
        print str(file_id) + " " + str(user_id)
        f = AESFiles.objects.get(file_id=file_id)
        u = AESUser.objects.get(index=user_id)
        recep = AESRecipient.objects.get(file_id=f, user_id=u)

        ret_data={
            'success': True,
            "rsa_skey": u.secret_rsa,
            "k": recep.k,
        }
    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    print ret_data
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def aes_keys_for_revocation(request):
    data = request.POST
    try:
        file_id = data['file_id']
        revoked_ids = data['revoke_set'].split()
        f = AESFiles.objects.get(file_id=file_id)
        fo = f.user_id
        recips = AESRecipient.objects.filter(file_id=f)

        ret_data={
            'success': True,
        }
        i = 0
        print 'revoke set' + str(revoked_ids)
        for receip in recips:
            if not (receip.user_id.box_id in revoked_ids):
                ret_data[str(i)+"_id"]=receip.user_id.box_id
                ret_data[str(i)+"_rsa"]=receip.user_id.public_rsa
                i+=1
        ret_data['NS']=i

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }

    data = json.dumps(ret_data)
    return HttpResponse(data, content_type='application/json')


@csrf_exempt
def aes_complete_revocation(request):
    try:
        data = request.POST
        file_id = data['file_id']
        print "AES revocking file: " + file_id
        #for u, v in data.iteritems():
        #    print u, v
        #    print "\n"
        f = AESFiles.objects.get(file_id = file_id)
        NS = int(data['NS'])
        ret_data={
            'success': True,
        }
        for i in range(NS):
            id = data[str(i)+'_id']
            new_keys = data[str(i)+'_key']
            r = AESUser.objects.get(box_id=id)
            aes_recip = AESRecipient.objects.get(file_id=f, user_id=r)
            aes_recip.diff_k = new_keys
            aes_recip.save()

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': True,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def aes_download_for_editing(request):
    try:
        data = request.POST
        print data
        file_id = data['file_id']
        user_id = data['user_id']
        print "AES request to edit file: " + file_id

        f = AESFiles.objects.get(file_id = file_id)
        u = AESUser.objects.get(box_id=user_id)
        r = AESRecipient.objects.get(file_id=f, user_id=u)
        ret_data={
            'success': True,
            'rsa_skey': u.secret_rsa,
            'diff_k': r.diff_k
        }

    except Exception as e:
        print "Error(s) happens" + str(e)
        ret_data={
            'success': True,
            'error': str(e)
        }

    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def aes_update_patch(request):
    try:
        data=request.POST
        token = data['access_token']
        file_id = data['file_id']
        content = data['content']
        pre_content = download_content_from_box(file_id, token)

        f=open("/tmp/temp.tmp", "w")
        f.write(pre_content.split("\n")[0])
        f.write(content + "\n")
        f.close()


        url = 'https://upload.box.com/api/2.0/files/'+file_id+'/content'
        auth = 'Bearer ' + token

        headers = {
            "Authorization": auth
        }

        f = open("/tmp/temp.tmp", "r")
        r = requests.post(url, headers=headers, files={'file': f})
        #print r.json()
        print "Done updating new content to Box" + str(file_id)

        ret_data={
            'success': True,
        }
    except Exception as e:
        print str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    data = json.dumps(ret_data)
    return HttpResponse(data, content_type='application/json')
