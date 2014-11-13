$(document).ready(function(){
    createRevokeView();

    //getCookies of tokens....
    getCookies("https://www.box.com", "tokens", function(){
        console.log("Token returned");
        if (!access_token){
            console.log("No cookies found");
            $("#login").click(startOauth);
        }
        else{
            console.log("Cookies found");
            $("#login").hide();
            getFolderItems('0');
            getUserInformation();
            firstTimeSetup();
        }
        $(".folder").live("click",viewFolder);
        $(".file").live("click",viewFile);
        $(".download").live("click", downloadProcess);
        $(".delete").live("click", deleteProcess);
        $("#id_submit").live("click", uploadProcess);
        $(".revoke").live("click", revokeProcess);
        $(".share").live("click", shareProcess);
    });
});

// ================FOR UPLOADING ======================
function uploadProcess(){
    folderId=$(this).attr("folder_id");
    var file = $("#upload_file")[0].files[0];
    if (!file){
        alert ("you haven't selected any file");
        return false;
    }

    var reader = new FileReader();
    reader.readAsText(file, "UTF-8");
    fileName = file.name;
    reader.onload = function (evt) {
        // reset the form file...
        var control = $("#upload_file");
        control.replaceWith( control = control.clone( true ));
        // and send the message
        startUpload(evt.target.result);
    }
}


/*
QUERY gbsHeader for global broadcast system
*/
function downloadParams(){
    if (typeof(gbsHeader) != "undefined")
        return gbsHeader;

    chrome.storage.local.get(['gbsHeader'], function(result) {
        if (typeof(result) !== "undefined" && result != null){
            gbsHeader = _base64ToArrayBuffer(result);
            dfdHeader.resolve();
            return;
        }
    });

    var oReq = new XMLHttpRequest();
    oReq.open("GET", THIRD_SERVER + 'get_gbs_params', true);
    oReq.responseType = "arraybuffer";

    oReq.onload = function (oEvent) {
        console.log("Get gbs params!");
        gbsHeader = oReq.response; // Note: not oReq.responseText
        chrome.storage.local.set({gbsHeader: _arrayBufferToBase64(gbsHeader)});
        dfdHeader.resolve();
    };

    oReq.send(null);
}

function startUpload(fileContent){
    downloadParams();
    $.when(dfdHeader.promise()).done(function(){
        console.log("Sending files to NACL");
        common.naclModule.postMessage({
                Cmd: 'Encryption',
                Content: fileContent,
                // Keys: keys,
                Fo: FILE_OWNER,
                Recipients: nReceipt,
                Headers: gbsHeader,
            });
    })
}

function doUpload(data){
    console.log("Done completing uploading...");
    var uploadUrl = 'https://upload.box.com/api/2.0/files/content';
    var dfd1 = $.Deferred();
    var fileId;
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };

    var form = new FormData();
    var blob = new Blob([data.main_cipher]);
    // console.log("ciphertext = " + _arrayBufferToBase64(data.main_cipher));
    // backupCipher = data.main_cipher;

    delete data.main_cipher;
    form.append('file_name', blob, fileName);
    form.append('parent_id', folderId);

    var args = {
        url: uploadUrl,
        headers: headers,
        crossDomain: true,
        type: 'POST',
        processData: false,
        contentType: false,
        data: form,
        success: function(data){
            console.log("Done uploading, file_id = " + data.entries[0].id);
            file_id = data.entries[0].id
            uploadComplete(file_id);
            dfd1.resolve();
            return;
        },
        error: function(request, status, error){
            console.log(request.responseText);
            return;
        },
    };
    $.ajax(args);

    $.when(dfd1.promise()).done(function(){
        var boxUrl = THIRD_SERVER + "upload_file";
        data.file_id = file_id;
        var args2 = {
            url: boxUrl,
            crossDomain: true,
            crossOrigin: true,
            contentType: 'application/x-www-form-urlencoded',
            type: 'POST',
            data: data,
            success: function (ret_data){
                console.log("Done uploading to the third server...")
            },
        };
        $.ajax(args2);
    });
}

/*
Append the new file to the folder view
*/
function uploadComplete(file_id){
    var content = "<tr class='file' name='" + fileName + "'lookup='" +
            file_id + "'><td><i class='icon-file'></i>" +
            fileName + "</td><td><button class='btn delete'>"
            + "<i class='icon-remove'></i>delete</button></td></tr>";
    $("#folder_view").append(content);
    $("#upload_file").empty();
}

//================= FOR DOWNLOADING ===============
function downloadProcess(){
    fileID = $(this).attr("lookup");
    fileName = $(this).attr("name");
    var dfd1 = $.Deferred();
    var dfd2 = $.Deferred();
    var ciphertext;

    //getting ciphertext from BOX
    var oReq = new XMLHttpRequest();
    var url = BOX_API_URL + 'files/'+fileID+"/content";
    oReq.open("GET", url, true);
    oReq.responseType = "arraybuffer";
    var auth = 'Bearer ' + getAccessToken();
    oReq.setRequestHeader("Authorization", auth);

    oReq.onload = function (oEvent){
        ciphertext = oReq.response; // Note: not oReq.responseText
        dfd1.resolve();
    };
    oReq.send(null);

    var url2 = THIRD_SERVER + 'download_file_params/'+ fileID + '/1'
    var fileParams;
    var args2 = {
        url: url2,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'json',
        type: 'GET',
        success: function (data) {
            fileParams = data;
            console.log("Done downloading file params...");
            dfd2.resolve();
        }
    };
    $.ajax(args2);

    downloadParams();
    // both are done;
    //send to NaCl module to decrypt the message
    $.when(dfd1.promise(), dfd2.promise(), dfdHeader.promise()).done(function(){
        console.log("Start decrypting process data...");

        common.naclModule.postMessage({
            Cmd: 'Decryption',
            n_shared: fileParams['n_shared'],
            o_n_shared: fileParams['o_n_shared'],
            Content: ciphertext,
            di: fileParams['di'],
            index: 1,
            C0: fileParams['C0'],
            C1: fileParams['C1'],
            OC0: fileParams['OC0'],
            OC1: fileParams['OC1'],
            Headers: gbsHeader,
        });
    });
}

function doneDecryption(data){
    console.log(JSON.stringify(data));
    console.log("Done completing decrypting...");
}

//=============== THIS IS FOR REVOCATION =================
function revokeProcess(){
    file_id = $(this).attr("lookup");
    fileName = $(this).attr("name");
    var revocation_keys;


        downloadParams();

    // query_keys_for_revocation(file_id);
    var url = THIRD_SERVER + 'query_keys_for_revocation/'+file_id+'/';
    $.when(dfdHeader.promise()).done(function(){
        var args = {
            url: url,
            crossDomain: true,
            crossOrigin: true,
            contentType: 'json',
            type: 'GET',
            success: function (data) {
                console.log("Done getting params");
                common.naclModule.postMessage({
                    Cmd: 'Revocation',
                    C0: data.C0,
                    C1: data.C1,
                    n_shared: data.n_shared,
                    n_revoked: nRevoke,
                    product: data.product,
                    Headers: gbsHeader,
                });
            },
        };
        $.ajax(args);
    });
}

function completeRevocation(data){
    console.log(JSON.stringify(data.k1));
    var url = THIRD_SERVER + 'complete_revocation/'+file_id+'/'+getAccessToken();
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'json',
        type: 'POST',
        contentType: 'application/x-www-form-urlencoded',
        data: data,
        success: function (ret_data) {
            console.log(JSON.stringify(ret_data));
        },
    };
    $.ajax(args);
}

//====================== FOR SHARING =======
function shareProcess(){
    file_id = $(this).attr("lookup");
    fileName = $(this).attr("name");
    var revocation_keys;


    downloadParams();

    $.when(dfdHeader.promise()).done(function(){
        var url = THIRD_SERVER + 'download_file_params_for_sharing/'+file_id+'/';
        var args = {
            url: url,
            crossDomain: true,
            crossOrigin: true,
            contentType: 'json',
            type: 'GET',
            success: function (data) {
                common.naclModule.postMessage({
                    Cmd: 'Sharing',
                    t: data.t,
                    C1: data.C1,
                    n_shared: data.n_shared,
                    n_new: nNewShare,
                    product: data.product,
                    Headers: gbsHeader,
                });
            },
        };
        $.ajax(args);
    });
}

function completeSharing(data){
    var url = THIRD_SERVER + 'complete_sharing/'+file_id;
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'json',
        type: 'POST',
        contentType: 'application/x-www-form-urlencoded',
        data: data,
        success: function (ret_data){
            console.log(JSON.stringify(ret_data));
        },
    };
    $.ajax(args);
}

//====================== MISCS =============
function testSendingBinaryData(){
    var bytesToSend = [253, 255, 128, 1, 5, 6],
    bytesToSendCount = bytesToSend.length;

    var bytesArray = new Uint8Array(bytesToSendCount);
    for (var i = 0, l = bytesToSendCount; i < l; i++) {
      bytesArray[i] = bytesToSend[i];
    };

    console.log("start sending binary data...");
    var form = new FormData();
    var blob = new Blob([bytesArray], {type: 'example/binary'});
    form.append('filename', blob, 'test.bin');

    $.ajax({
       url: THIRD_SERVER + 'test_binary',
       type: 'POST',
       data: form,
       processData: false,
       contentType: false,
       success: function(data){
          console.log('test_binary ' + JSON.stringify(data));
       }
    });
}


//================ FOR DELETE==========
function deleteProcess(e){
    e.preventDefault();
    e.stopPropagation();
    file_id = $(this).closest('tr').attr("lookup");
    $(this).closest('tr').hide();
    var url = 'https://api.box.com/2.0/files/'+file_id;
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };

    var args = {
        url: url,
        headers: headers,
        crossDomain: true,
        type: 'DELETE',
        contentType: false,
        success: function(data){
            console.log("Done deleting, file_id = " + file_id);
            return;
        },
        error: function(request, status, error){
            console.log(request.responseText);
            return;
        },
    };
    $.ajax(args);
}