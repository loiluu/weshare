from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()
import views
import settings
import aes_views
from django.views.static import serve

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'third_server.views.home', name='home'),
    url(r'^$', views.index, name='index'),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^setup$', views.setup, name='setup'),
    url(r'^get_gbs_params$', views.get_gbs_params, name='get_gbs_params'),
    url(r'^get_rsa_keys$', views.get_rsa_keys, name='get_rsa_keys'),
    url(r'^upload_file$', views.upload_file, name='upload_file'),
    url(r'^download_file_params/(?P<file_id>\w+)/(?P<index>\d+)$',
        views.download_file_params_for_decryption, name='download_file_params'),
    url(r'^query_keys_for_revocation/(?P<file_id>\w+)/$',
        views.download_file_params_for_revocation, name='revocation_download'),
    url(r'^complete_revocation/(?P<file_id>\w+)/(?P<access_token>[a-zA-Z0-9_.@-]+)$',
        views.complete_revocation, name='complete_revocation'),

    url(r'^download_file_params_for_sharing/(?P<file_id>\w+)/$',
        views.download_file_params_for_sharing, name='sharing_download'),
    url(r'^complete_sharing/(?P<file_id>\w+)$',
        views.complete_sharing, name='complete_sharing'),
    url(r'^first_time_user_setup/(?P<user_id>[a-zA-Z0-9_.@-]+)$',
        views.first_time_setup, name='first_time_user_setup'),
    url(r'^complete_user_setup$',
        views.complete_user_setup, name='complete_user_setup'),

    url(r'^test_binary$', views.test_binary, name='test_binary'),

    # url(r'^download/(?P<file_id>\w+)/(?P<user_id>[a-zA-Z0-9_.@-]+)/$', views.demo_download, name='demo_download'),
    url(r'^download_box/(?P<file_id>\w+)/(?P<access_token>[a-zA-Z0-9_.@-]+)$',
        views.demo_download_from_box, name='demo_download_from_box'),
    # url(r'^complete_revocation$', views.complete_revocation, name='complete_revocation'),

    url(r'^aes_get_rsa_list$', aes_views.aes_get_rsa_list, name='aes_keys_query'),
    url(r'^aes_query_keys$', aes_views.aes_query_keys, name='aes_keys_query'),
    url(r'^aes_complete_upload$', aes_views.aes_complete_upload, name='aes_complete'),
    url(r'^aes_download/(?P<file_id>\w+)/(?P<user_id>[a-zA-Z0-9_.@-]+)$', aes_views.aes_download, name='aes_download'),
    url(r'^aes_keys_for_revocation$', aes_views.aes_keys_for_revocation, name='aes_revocation_download'),
    url(r'^aes_complete_revocation$', aes_views.aes_complete_revocation, name='aes_complete_revocation'),
    url(r'^aes_download_for_editing$', aes_views.aes_download_for_editing, name='aes_download_for_editing'),
    url(r'^aes_update_patch/$', aes_views.aes_update_patch, name='aes_update_patch'),


    #enable admin interface
    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^weshare/static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
    url(r'^weshare/media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
)
