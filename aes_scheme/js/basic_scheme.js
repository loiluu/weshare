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
    });
});

// ================FOR DOWNLOADING =====================
function completeDownloadFile(data){
    console.log(JSON.stringify(data));
    console.log("Done completing decrypting...");
}


function downloadProcess(){
    file_id = $(this).attr("lookup");
    fileName = $(this).attr("name");
    //send to NaCl module to decrypt the message
    var dfd1 = $.Deferred();
    var dfd2 = $.Deferred();
    var ciphertext;
    var naclData;

    //getting ciphertext from BOX
    var oReq = new XMLHttpRequest();
    var url = BOX_API_URL + 'files/'+file_id+"/content";
    oReq.open("GET", url, true);
    oReq.responseType = "arraybuffer";
    var auth = 'Bearer ' + getAccessToken();
    oReq.setRequestHeader("Authorization", auth);

    oReq.onload = function (oEvent){
        ciphertext = oReq.response; // Note: not oReq.responseText
        dfd1.resolve();
    };
    oReq.send(null);

    var url2 = THIRD_SERVER + 'aes_download/'+file_id+"/"+FILE_OWNER;
    var args2 = {
        url: url2,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'json',
        type: 'GET',
        success: function (data){
            naclData = data;
            dfd2.resolve();
        }
    };
    $.ajax(args2);

    $.when(dfd1.promise(), dfd2.promise()).done(function(){
        console.log("Start decrypting process data...");

        common.naclModule.postMessage({
            Cmd: 'Decryption',
            Content: ciphertext,
            k: naclData.k,
            rsa_skey: naclData.rsa_skey
        });
    });
}

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
        // postMessage sends a message to it.
        common.naclModule.postMessage({ Cmd: "Encryption",
                                        Content: evt.target.result,
                                        RSA_List: rsaList,
                                        fo: FILE_OWNER,
                                        nReceipt: nReceipt})


    }
}

/*
This will be called when the encryption done
Send the encrypted data to the server
 */
function doUpload(data){
    var uploadUrl = 'https://upload.box.com/api/2.0/files/content';
    var dfd1 = $.Deferred();
    var fileId;
    var headers = {
        Authorization: 'Bearer ' + getAccessToken()
    };

    var form = new FormData();
    var blob = new Blob([data.aes_cipher]);

    delete data.aes_cipher;
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
        var boxUrl = THIRD_SERVER + "aes_complete_upload";
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