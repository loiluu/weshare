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
NUM_USERS = 10

def index(request):
    return HttpResponse("Hello, world. You're at WEShare's homepage.")

#This is the setup process to generate all g_i component. Run it once and only, otherwise it will
#invade the whole system.
def setup(request):
    try:
        process = subprocess.check_output(PROJECT_ROOT+"/../backend/mainbgw setup " + str(NUM_USERS), shell=True,\
                                          stderr=subprocess.STDOUT)
        f = open("/tmp/gbs2.txt", "r")
        ind=-1
        for line in f:
            ind+=1
            #pass the first and second lines
            if ind < 1:
                continue
            if ind == NUM_USERS+1:
                break

            private = RSA.generate(1024)
            public = private.publickey()
            new_user = User(index=ind, public_rsa=public.exportKey(), secret_rsa=private.exportKey(), gi=line)
            new_user.save()

            new_aes_user = AESUser(index=ind, public_rsa=public.exportKey(), secret_rsa=private.exportKey())
            new_aes_user.save()

        f.close()
        return HttpResponse("Done setting up...")

    except Exception as e:
        print "Error on setup" + str(e)
        raise e

@csrf_exempt
def get_gbs_params(request):
    wrapper = FileWrapper(file("/tmp/gbs.txt"))
    response = HttpResponse(wrapper, content_type='application/zip')
    response['Content-Disposition'] = 'attachment; filename=gbs.txt'
    return response


#This is to check which users are not shared the g_i^z component
#if they are not shared, send the rsa public key to the file owner
@csrf_exempt
def get_rsa_keys(request):
    data = request.POST
    try:
        receip_ids = int(data['recipient'])
        fo_id = data['fo']
        user_a = User.objects.get(index=fo_id)
        i=0
        ret_data = {}
        for id in range(receip_ids):
            try:
                user_b = User.objects.get(index=id+1)
                try:
                    recip = Recipient.objects.get(user_a=user_a, user_b=user_b)
                except Exception as e:
                    recip = Recipient(user_a=user_a, user_b=user_b)
                    recip.save()
                if recip.di:
                    continue
                ret_data[str(i)+"_rsa"] = user_b.public_rsa
                ret_data[str(i)+"_id"] = id+1
                i+=1
            except Exception as e:
                print "Error when querying the di of user  " + str(i)
                raise e
        ret_data['new_shared'] = i
    except Exception as e:
        print "Errors " + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

#Uploads and stores all the parameters when uploading file,
#including C0, C1, all the di of other recipients..
@csrf_exempt
def upload_file(request):
    try:
        ret_data={
            'success': False
        }
        data = request.POST
        print data
        file_id = data['file_id']
        fo_id = data['Fo']
        try:
            fo = User.objects.get(index=fo_id)
        except Exception as e:
            print "user doesn't exist..."
            raise e

        C0 = data['C0']
        C1 = data['C1']
        prod = data['product']
        n_shared = int(data['n_shared'])
        t = data['t']
        k1 = data['k1']
        try:
            new_file = FileDB(file_id=file_id, user_id=fo, C0=C0, C1=C1, OC0=C0, OC1=C1, product=prod,\
                              n_shared=n_shared, o_n_shared=n_shared, t=t, k1=k1)
            new_file.save()
        except Exception as e:
            print "Error on saving file"
            raise e

    except Exception as e:
        print 'Error here' + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    jsdata = json.dumps(ret_data)
    return HttpResponse(jsdata, content_type='application/json')

@csrf_exempt
def download_file_params_for_decryption(request, file_id, index):
    try:
        file = FileDB.objects.get(file_id=file_id)
        fo = file.user_id
        user_b = User.objects.get(index=index)
        recip = Recipient.objects.get(user_a=fo, user_b=user_b)
        ret_data={
            'success': True,
            'C0': file.C0,
            'C1': file.C1,
            'OC0': file.OC0,
            'OC1': file.OC1,
            'di': recip.di,
            'n_shared': file.n_shared,
            'o_n_shared': file.o_n_shared
        }
    except Exception as e:
        print e
        ret_data={
            'success': False,
            'error': str(e)
        }
    jsdata = json.dumps(ret_data)
    return HttpResponse(jsdata, content_type='application/json')

def download_file_params_for_revocation(request, file_id):
    try:
        file = FileDB.objects.get(file_id=file_id)
        fo = file.user_id
        ret_data={
            'success': True,
            'C0': file.C0,
            'C1': file.C1,
            'product': file.product,
            'n_shared': file.n_shared
        }
    except Exception as e:
        print e
        ret_data={
            'success': False,
            'error': str(e)
        }
    jsdata = json.dumps(ret_data)
    return HttpResponse(jsdata, content_type='application/json')

def download_file_params_for_sharing(request, file_id):
    try:
        f = FileDB.objects.get(file_id=file_id)
        ret_data={
            'success': True,
            'C1': f.C1,
            'product': f.product,
            'n_shared': f.n_shared,
            't': f.t,
        }
    except Exception as e:
        print e
        ret_data={
            'success': False,
            'error': str(e)
        }
    jsdata = json.dumps(ret_data)
    return HttpResponse(jsdata, content_type='application/json')

def demo_download_from_box(request, file_id, access_token):
    #16600831793/IwsXugGtipPIKMKODaAnYYmjHRGwmOAp
    url = 'https://api.box.com/2.0/files/' + file_id + '/content'
    auth = 'Bearer ' + access_token
    payload = {
        'crossDomain': True,
        'dataType': 'json',
        'content-type': 'application/json'
    }
    #print payload
    headers = {
        "Authorization": auth
    }
    while True:
        r = requests.get(url, data=json.dumps(payload), headers=headers)
        if len(r.text):
            break
    #print "This is the splitter"
    some_data_to_dump = {
       'content': r.text,
    }
    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')


@csrf_exempt
def complete_revocation(request, file_id, access_token):
    try:
        url = 'https://api.box.com/2.0/files/' + file_id + '/content'
        auth = 'Bearer ' + access_token

        headers = {
            "Authorization": auth
        }
        with open("/tmp/"+str(file_id), 'wb') as handle:
            response = requests.get(url, headers=headers, stream=True)
            if not response.ok:
                raise Exception("Something went wrong")

            for block in response.iter_content(1024):
                if not block:
                    break
                handle.write(block)

        current_file = FileDB.objects.get(file_id=file_id)
        #write the previous and new k1 to the file so the backend can read it
        f = open("/tmp/k.txt", "w")
        f.write(current_file.k1)
        f.write("\n")
        f.write(request.POST['k1'])
        f.close()
        #update the file DB
        current_file.k1 = request.POST['k1']
        current_file.C0 = request.POST['C0']
        current_file.C1 = request.POST['C1']
        current_file.t = request.POST['t']
        current_file.n_shared = int(request.POST['n_shared'])
        current_file.product = request.POST['product']
        current_file.save()

        #call the backend to update the contents
        process = subprocess.check_output(PROJECT_ROOT+"/../backend/mainbgw revoke " + str(file_id), shell=True,\
                                          stderr=subprocess.STDOUT)
        update_to_box(file_id, "/tmp/"+str(file_id), access_token)
        some_data_to_dump = {
           'success': True,
           'content': 'Successfully updated'
        }
    except Exception as e:
        print e
        some_data_to_dump = {
           'success': False,
           'content': str(e)
        }


    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')

@csrf_exempt
def complete_sharing(request, file_id):
    try:
        current_file = FileDB.objects.get(file_id=file_id)
        #update the file DB
        current_file.C1 = request.POST['C1']
        current_file.n_shared = int(request.POST['n_shared'])
        current_file.product = request.POST['product']
        current_file.save()
        some_data_to_dump = {
           'success': True,
           'content': 'Successfully shared'
        }
    except Exception as e:
        print str(e)
        some_data_to_dump = {
           'success': False,
           'content': str(e)
        }


    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')

@csrf_exempt
def first_time_setup(request, user_id):
    try:
        user_a = User.objects.get(index=user_id)
        i=0
        ret_data = {}
        for id in range(NUM_USERS):
            try:
                user_b = User.objects.get(index=id+1)
                try:
                    recip = Recipient.objects.get(user_a=user_a, user_b=user_b)
                except Exception as e:
                    recip = Recipient(user_a=user_a, user_b=user_b)
                    recip.save()
                if recip.di:
                    continue
                ret_data[str(i)+"_rsa"] = user_b.public_rsa
                ret_data[str(i)+"_id"] = id+1
                i+=1
            except Exception as e:
                print "Error when querying the di of user  " + str(i)
                raise e
        ret_data['new_shared'] = i
    except Exception as e:
        print "Errors " + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    rdata = json.dumps(ret_data)
    return HttpResponse(rdata, content_type='application/json')

@csrf_exempt
def complete_user_setup(request):
    try:
        data = request.POST.copy()
        print data
        ret_data = {}
        fo_id = data['Fo']
        try:
            fo = User.objects.get(index=fo_id)
        except Exception as e:
            print "user doesn't exist..."
            raise e

        for i in range(NUM_USERS):
            key_id = str(i)+"_id"
            id = data[key_id]
            key_di = str(i)+"_di"
            di = data[key_di]
            try:
                user_i = User.objects.get(index=id)
            except Exception as e:
                print key_id + "Doesn't exist..."
                raise e
            try:
                recip = Recipient.objects.get(user_a=fo, user_b=user_i)
                recip.di=di
                recip.save()
                ret_data[i] = True
            except Exception as e:
                print "Recip doesn't exist: " + str(i)
                raise e

    except Exception as e:
        print 'Error here' + str(e)
        ret_data={
            'success': False,
            'error': str(e)
        }
    jsdata = json.dumps(ret_data)
    return HttpResponse(jsdata, content_type='application/json')


@csrf_exempt
def test_binary(request):
    try:
        data=request.FILES['filename']
        with open('/tmp/output', 'wb+') as destination:
            for chunk in data.chunks():
                destination.write(chunk)
        print data
        some_data_to_dump = {
           'success': True,
           'content': 'None'
        }
    except Exception as e:
        some_data_to_dump = {
           'success': False,
           'content': 'None'
        }
        print e
    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')

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
def complete_revocation(request, file_id, access_token):
    try:
        url = 'https://api.box.com/2.0/files/' + file_id + '/content'
        auth = 'Bearer ' + access_token

        headers = {
            "Authorization": auth
        }
        with open("/tmp/"+str(file_id), 'wb') as handle:
            response = requests.get(url, headers=headers, stream=True)
            if not response.ok:
                raise Exception("Something went wrong")

            for block in response.iter_content(1024):
                if not block:
                    break
                handle.write(block)

        print request.POST
        current_file = FileDB.objects.get(file_id=file_id)
        #write the previous and new k1 to the file so the backend can read it
        f = open("/tmp/k.txt", "w")
        f.write(current_file.k1)
        f.write("\n")
        f.write(request.POST['k1'])
        f.close()
        #update the file DB
        current_file.k1 = request.POST['k1']
        current_file.C0 = request.POST['C0']
        current_file.C1 = request.POST['C1']
        current_file.t = request.POST['t']
        current_file.n_shared = int(request.POST['n_shared'])
        current_file.product = request.POST['product']
        current_file.save()

        #call the backend to update the contents
        process = subprocess.check_output(PROJECT_ROOT+"/../backend/mainbgw revoke " + str(file_id), shell=True,\
                                          stderr=subprocess.STDOUT)
        update_to_box(file_id, "/tmp/"+str(file_id), access_token)
        some_data_to_dump = {
           'success': True,
           'content': 'Successfully updated'
        }
    except Exception as e:
        print e
        some_data_to_dump = {
           'success': False,
           'content': str(e)
        }


    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')

@csrf_exempt
def test_binary(request):
    try:
        data=request.FILES['filename']
        with open('/tmp/output', 'wb+') as destination:
            for chunk in data.chunks():
                destination.write(chunk)
        print data
        some_data_to_dump = {
           'success': True,
           'content': 'None'
        }
    except Exception as e:
        some_data_to_dump = {
           'success': False,
           'content': 'None'
        }
        print e
    data = json.dumps(some_data_to_dump)
    return HttpResponse(data, content_type='application/json')