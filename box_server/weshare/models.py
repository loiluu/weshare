from django.db import models

# Create your models here.
# -*- coding: utf-8 -*-
from django.db import models
from django.forms.models import ModelChoiceField
import datetime
from django.contrib import admin
MAX_ELEMENT_LEN = 1000
MAX_ID_LEN = 100
MAX_RSA_PUB_KEY = 1000
MAX_RSA_SEC_KEY = 4090

class User(models.Model):
    index = models.IntegerField("Index in GBS", unique=True)
    public_rsa = models.CharField("RSA Public key", max_length=MAX_RSA_PUB_KEY)
    secret_rsa = models.CharField("RSA Secret key", max_length=MAX_RSA_SEC_KEY)
    gi = models.CharField("Public key (component g_i)", max_length=MAX_ELEMENT_LEN)
    # z = models.CharField("Secret z", max_length=MAX_ELEMENT_LEN)
    # gamma = models.CharField("Secret gamma", max_length=MAX_ELEMENT_LEN)

    def __unicode__(self):
        return unicode("User: ") + unicode(self.index)


class FileDB(models.Model):
    file_id = models.CharField("File ID", max_length=MAX_ID_LEN, unique=True)
    user_id = models.ForeignKey(User, verbose_name="Owner ID", null=False, blank=False)
    #this is blinded factors
    C0 = models.CharField("Public header C0", max_length=MAX_ELEMENT_LEN)
    C1 = models.CharField("Public header C1", max_length=MAX_ELEMENT_LEN)
    OC0 = models.CharField("Original Public header C0", max_length=MAX_ELEMENT_LEN)
    OC1 = models.CharField("Original Public header C1", max_length=MAX_ELEMENT_LEN)
    product = models.CharField("Secret product", max_length=MAX_ELEMENT_LEN)
    t = models.CharField("Secret t", max_length=MAX_ELEMENT_LEN)
    n_shared = models.IntegerField("No. of recipients")
    o_n_shared = models.IntegerField("Original No. of recipients")
    k1 = models.CharField("Secret K1", max_length=MAX_ELEMENT_LEN)

    class Meta:
        unique_together = ('file_id', 'user_id')

    def __unicode__(self):
        return unicode("File ID: ") + unicode(self.file_id)


class Recipient(models.Model):
    user_a = models.ForeignKey(User, related_name='sender', verbose_name="Sender", null=False, blank=False)
    user_b = models.ForeignKey(User, related_name='receiver', verbose_name="Receiver", null=False, blank=False)
    di = models.CharField("gi^gamma*g^z)", max_length=MAX_ELEMENT_LEN, default=None, null=True)

    class Meta:
        unique_together = ('user_a', 'user_b')

    def __unicode__(self):
        return unicode(unicode(self.user_a) + " shared to " + unicode(self.user_b))


class AESUser(models.Model):
    index = models.IntegerField("Index of User", unique=True)
    public_rsa = models.CharField("RSA Public key", max_length=MAX_RSA_PUB_KEY)
    secret_rsa = models.CharField("RSA Secret key", max_length=MAX_RSA_SEC_KEY)

    def __unicode__(self):
        return unicode("UserID: ") + unicode(self.index)


class AESFiles(models.Model):
    file_id = models.CharField("File ID", max_length=MAX_ID_LEN, unique=True)
    user_id = models.ForeignKey(AESUser, verbose_name="Creator ID", null=False, blank=False)
    NS = models.IntegerField("No. of recipients")

    def __unicode__(self):
        return unicode("FileID: ") + unicode(self.file_id)

class AESRecipient(models.Model):
    file_id = models.ForeignKey(AESFiles, verbose_name="File ID", null=False, blank=False)
    user_id = models.ForeignKey(AESUser, verbose_name="User ID", null=False, blank=False)
    k = models.CharField("AES Key", max_length=MAX_ELEMENT_LEN)

    class Meta:
        unique_together = ('file_id', 'user_id')

    def __unicode__(self):
        return unicode(unicode(self.file_id) + " shared to " + unicode(self.user_id))




admin.site.register(User)
admin.site.register(FileDB)
admin.site.register(Recipient)
admin.site.register(AESUser)
admin.site.register(AESRecipient)
admin.site.register(AESFiles)