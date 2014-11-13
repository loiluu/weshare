var THIRD_SERVER = "http://54.186.188.1/"
// var THIRD_SERVER = "http://localhost:8000/";
var BLOCK_SIZE = 32;
var BOX_API_URL = "https://api.box.com/2.0/";
var token_split = '---';

var gbsHeader;
var dfdHeader = $.Deferred();
var fileName;
var folderId;
var file_id;

//Some const
var nReceipt = 8;
var nRevoke = 3;
var nNewShare = 1;
var FILE_OWNER = 1;

//some global variables for box authentication
var access_token;
var refresh_token;
var set_time;
var OauthParams;


function getCookies(domain, name, callback) {
    console.log("Getting cookies...");
    chrome.cookies.get({"url": domain, "name": name}, function(cookie) {
        if(callback){
            console.log("Done getting cookies, calling back...");
            console.log(cookie);
            if (typeof cookie == "undefined" || cookie == null){
                console.log("cookie is empty..")
                callback();
            }
            else{
                console.log("cookie is not empty..")
                var tmp = cookie.value.split(token_split);
                access_token = tmp[0];
                refresh_token = tmp[1];
                set_time = parseInt(tmp[2]);
                var currentTime = new Date().getTime()/1000;
                //if the access_token is valid for 10 mins only, request the new one..
                if (currentTime - set_time > 3000)
                    queryNewToken(callback);
                else
                    callback();
            }
        }
    });
}
//convert from arrayBuffer to Base64
function _arrayBufferToBase64( buffer ) {
    var binary = ''
    var bytes = new Uint8Array( buffer )
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++)
        binary += String.fromCharCode( bytes[i] );
    return window.btoa( binary );
}

//convert from Base64 to arrayBuffer
function _base64ToArrayBuffer(base64){
    var binary_string =  window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array( len );
    for (var i = 0; i < len; i++)
        bytes[i] = binary_string.charCodeAt(i);
    return bytes.buffer;
}

//Return true when |s| starts with the string |postfix|.
function endsWith(str, suffix) {
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
}


function setOauthParams(oauthParamsPassed) {
    OauthParams = oauthParamsPassed;
}

function getOauthParams() {
    return OauthParams;
}


function setTokens(TokensPass){
    access_token=TokensPass.access_token;
    refresh_token=TokensPass.refresh_token;
    set_time = new Date().getTime()/1000;
    //set the expire date for the refresh token as 10 days...
    var expireDate = new Date().getTime()/1000 + 864000;
    var tokens = access_token + token_split + refresh_token + token_split + set_time;
    chrome.cookies.set({"url": "https://www.box.com",
                        "name": "tokens",
                        "value": tokens,
                        "expirationDate": expireDate}, function(cookie){
        console.log("Cookie set");
        console.log(cookie);
    });
}

function removeTokens(){
    access_token = 0;
    refresh_token = 0;
}


function getRefreshToken(){
    return refresh_token;
}

function queryNewToken(callback){
    console.log("Getting new access token since the previous is expired..")
    var url = 'https://www.box.com/api/oauth2/token';
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'application/x-www-form-urlencoded',
        type: 'POST',
        data: {
            grant_type: 'refresh_token',
            refresh_token: getRefreshToken(),
            client_id: clientId,
            client_secret: clientsecret
        },
        success: function (data) {
            setTokens(data);
            callback();
        }
    };
    $.ajax(args);
}

function getAccessToken(){
    var currentTime = new Date().getTime()/1000;
    //if the access_token is valid for 10 mins only, request the new one..
    if (currentTime - set_time > 3000)
        queryNewToken(function (){
            return access_token;
        });
    else
        return access_token;
}


function auth(){
    var oauthParams = getOauthParams();
    var url = 'https://www.box.com/api/oauth2/token';
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'application/x-www-form-urlencoded',
        type: 'POST',
        data: {
            grant_type: 'authorization_code',
            code: oauthParams,
            client_id: clientId,
            client_secret: clientsecret
        },
        success: function (data) {
            setTokens(data);
            $("#login").hide();
            getFolderItems('0');
            getUserInformation();
            firstTimeSetup();
        }
    };
    $.ajax(args);
}

function refreshToken(){
    var token = getRefreshToken();
    var url = 'https://www.box.com/api/oauth2/token';
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'application/x-www-form-urlencoded',
        type: 'POST',
        data: {
            grant_type: 'refresh_token',
            refresh_token: token,
            client_id: clientId,
            client_secret: clientsecret
        },
        success: function (data) {
            setTokens(data);
        }
    };
    $.ajax(args);
}

function revoke(){
    var token = getRefreshToken();
    var url = 'https://www.box.com/api/oauth2/revoke';
    var args = {
        url: url,
        crossDomain: true,
        crossOrigin: true,
        contentType: 'application/x-www-form-urlencoded',
        type: 'POST',
        data: {
            token: token,
            client_id: clientId,
            client_secret: clientsecret
        },
        success: function () {
            $("#login").show();
            $("#logout").hide();
            removeTokens();
            createRevokeView();
        }
    };
    $.ajax(args);
}

function createRevokeView(){
    var content = "<p>Please login to use the system.</p>";
    $("#id_content").html(content);
    $("#display_infor").empty();
}

function getUserInformation(){
    var url = "https://api.box.com/2.0/users/me";
    var auth = 'Bearer ' + getAccessToken();
    var headers = {
        Authorization: auth
    };
    var args = {
        url: url,
        headers: headers,
        type: 'GET',
        dataType: "json",
        success: function (data) {
            var content = "<table class='table table-hover'><tbody>";
            content += "<tr><td><img src=\"" + data.avatar_url + "\"/></td><td>" + data.name + "</td></tr>";
            content += "<tr><td>Email</td><td>" + data.login + "</td></tr>";
            content += "<tr><td>Space amount</td><td>" + (data.space_amount/(1024*1024)).toFixed(2) + " MB</td></tr>";
            content += "<tr><td>Space used</td><td>" + (data.space_used/(1024*1024)).toFixed(2) + " MB</td></tr>";
            content += "<tr><td>Status</td><td>" + data.status + "</td></tr>";
            content += "</tbody></table>";
            $("#display_infor").html(content);
            $("#userinfor").hide();
        }
    };
    $.ajax(args);
}

function getFolderItems(FOLDERID){
    var url = 'https://api.box.com/2.0/folders/' + FOLDERID + '/items';
    var auth = 'Bearer ' + getAccessToken();
    console.log(auth);
    var headers = {
        Authorization: auth
    };
    var args = {
        url: url,
        headers: headers,
        type: 'GET',
        success: function (data) {
            createFolderViews(data.entries, FOLDERID);
        }
    };
    $.ajax(args);
}

function createFolderViews(entries, FOLDERID){
    var table = "<table id='folder_view' class='table table-hover'><thead><th>Name</th></thead><tbody>";
    var tr = "<tr><td> <input type=\"file\" name=\"file\" id=\"upload_file\">";
    tr += "<button type=\"submit\" name=\"submit\" id=\"id_submit\" folder_id=\"" + FOLDERID + "\"><i class='icon-upload'></i>Upload</button></td><td></td></tr>";
    table += tr;

    $.each(entries, function(key,val){
        var tr;
        if(val.type == "folder"){
            tr = "<tr class='folder' name='" + val.name
                    + "'lookup='"+ val.id + "'><td><i class='icon-folder-open'></i>";
            tr += val.name + "</td><td></td>" + "</tr>";
        }
        else{
            tr = "<tr class='file'  name='" + val.name
                + "'lookup='"+ val.id + "'><td><i class='icon-file'></i>";
                tr += val.name + "</td><td><button class='btn delete'><i class='icon-remove'></i>delete</button></td></tr>";
        }

        table += tr;
    });
    table += "</tbody></table>";

    $("#id_content").html(table);
}

function viewFolder(){
    var folder_id = $(this).attr("lookup");
    $("#iframe").html("");
    getFolderItems(folder_id);
    if ($(this).is("li")){
        $(this).nextAll().remove();
    }
    else{
        var folder_name =  $(this).attr("name");
        var crumb = '<li class="folder" lookup="' + folder_id + '"><a>'
            + folder_name + '</a> <span class="divider">/</span></li>';
        $("#id_breadcrumb").append(crumb);
    }
}


// ============ FILE PROCESSS ===================
function getFileInfo(){
    var url = 'https://api.box.com/2.0/files/' + file_id;
    var auth = 'Bearer ' + getAccessToken();
    var headers = {
        Authorization: auth
    };
    var args = {
        url: url,
        headers: headers,
        type: 'GET',
        success: function (data) {
            createFileViews(data);
        }
    };
    $.ajax(args);
}

function createFileViews(data){
    var tr = "<tr><td></td><td> <input type='file' name='file' id='upload_file'>";
    tr += "<input type='submit' name='submit' id='update_submit' value='Update' file_id='" + data.id
        +"' file_name='" + data.name + "'></td></tr>";

    var content = "<h3></h3><table class='table table-hover'><tbody>";
    //content += tr;
    content += "<tr><th>Name</th><th>" + data.name + "</th></tr>";
    content += "<tr><th>Size</th><th>" + (data.size) + "B</th></tr>";
    content += "<tr><th>Description</th><th>" + data.description + "</th></tr>";
    content += "<tr><th>Last modified</th><th>" + data.modified_at + "</th></tr>";
    content += "<tr><th>SHA1</th><th>" + data.sha1 + "</th></tr>";
    content += "<tr><th></th> <th><button class='btn download' lookup='"
            + data.id + "'><i class='icon-download'></i>Download</button>" +
            "<button class='btn revoke' lookup='"
            + data.id + "'><i class='icon-refresh'></i>Revoke Users</button>" +
            "<button class='btn share' lookup='"
            + data.id + "'><i class='icon-share'></i>Share More</button>" +
            "</th></tr>";
    content += "</tbody></table>";

    $("#id_content").html(content);
    // test_download_api(data.id);
}

function viewFile(){
    file_id = $(this).attr("lookup");
    getFileInfo();
}

function startOauth(){
    var authUrl = 'https://www.box.com/api/oauth2/authorize';
    authUrl += '?response_type=code&client_id='
            + encodeURIComponent(clientId)
            + '&state=authenticated'
            + '&redirect_uri=' + encodeURIComponent(redirectUri);

    chrome.identity.launchWebAuthFlow({url: authUrl, interactive: true},
        function(responseUrl) {
      var oauthParameter = responseUrl.substring(responseUrl.indexOf("code=") + 5);
      setOauthParams(oauthParameter);
      auth();
    });
}

//================ FOR INITIAL SETUP ==============
function firstTimeSetup(){
    downloadParams();
    $.when(dfdHeader.promise()).done(function(){
        $.ajax({
            url: THIRD_SERVER + 'first_time_user_setup/' + FILE_OWNER,
            type: 'GET',
            crossDomain: true,
            crossOrigin: true,
            contentType: 'json',
            success: function(data){
                if (data.new_shared > 0){
                    console.log("Get d_i for " + data.new_shared + " users");
                    common.naclModule.postMessage({
                        Cmd: 'Setup',
                        Keys: data,
                        Fo: FILE_OWNER,
                        Headers: gbsHeader,
                    });
                }
                else{
                    console.log("All users get their d_i already");
                }
           }
        });
    });
}

function completeSetup(data){
    $.ajax({
        url: THIRD_SERVER + 'complete_user_setup',
        type: 'POST',
        crossDomain: true,
        crossOrigin: true,
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        success: function(data){
            console.log("Done setting up");
       }
    });
}