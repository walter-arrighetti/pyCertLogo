#!/usr/bin/python
##########################################################
#  x509certLogos  0.2                                    #
#                                                        #
#    conforms with:                                      #
#         RFC-3709: Logotypes in X.509 Certificates      #
#         RFC-6170: Cerificate Image                     #
#                                                        #
#    Copyright (C) 2023 Walter Arrighetti, Ph.D.         #
#    All Rights Reserved.                                #
##########################################################
VERSION = "0.2"
## This version of the spec does NOT check:
##   * if the SVG logo conforms with W3C's SVG Tiny 1.2 specs
##   * if the PNG logo conforms with ISO-15948 specs
##   * if the PDF logo conforms with PDF/A specs from ISO 32000
##   * if the language tags for audio logos conforms with RFC-3066
import hashlib
import zipfile
import base64
import os
import io
import re


def main():
	import argparse
	import sys
	args = argparse.ArgumentParser(description="Takes one or several GIF/JPEG/PNG/SVG(Z) images and MP3 audio as input and returns a one-section OpenSSL configuration file to be used as a single X509v3 extension for a certificate to generate including those files as certificate logotypes/images, as per RFC-3709 and RFC-6170.")
	logotypeExt = x509LogotypeExtension()
	#print(x509logotypeData("certs/logos/WA-logo_subCA_Systems-color.png",hashtype="sha256").struct(0))
	if not logotypeExt.Issuer(x509logotypeData("certs/logos/WA-logo_subCA_Systems-color.png",hashtype="sha256")):
		print("ERROR!!")
	logotypeExt.exportConfig("logotype.cnf")
	#args.add_argument()
	




class OID:
	def __init__(self, oid0, *OIDs, label=None):
		self.oid, self.name, self.label, self.depth = None, None, None, 0
		if not oid0 or (label and not self.___labelize(label)):	return None
		elif type(oid0)==type(1):	oid0 = [str(oid0)]
		elif type(oid0) in [type([]),type(tuple([]))]:	oid0 = list(map(str,oid0))
		elif isinstance(oid0,OID):	oid0 = list(oid0.oid)
		elif type(oid0)==type(""):	oid0 = oid0.split('.')
		else:	return None
		for oid in OIDs:
			if type(oid)==type(""):	oid0.expand(oid.split('.'))
			elif type(oid)==type(1):	oid0.append(str(oid))
			elif type(oid) in [type([]),type(tuple([]))]:	oid0.expand(list(map(str,oid)))
			elif isinstance(oid,OID):	oid0.expand(list(oid.oid))
			else:	return None
		try:	oid0 = list(map(int,oid0))
		except:	return None
		self.oid, self.depth = tuple(oid0), len(oid0)
		self.label = self.___labelize(label)
		if type(self.label)==type([]):
			if len(self.label)>1:
				if self.depth!=len(self.label):	return None
				self.label = '.'.join(self.label)
			else:
				self.label = self.label[0]
		#if self.label==False:	pass
		if self.label:	self.name = self.label
		else:	self.name = self.__repr__()
	def __repr__(self):	return '.'.join(list(map(str,self.oid)))
	def __str__(self):	return self.name
	def ___labelize(self,label):
		def __islabel(s):
			if not s:	return False
			s = s.strip().translate({'.':'-'})
			if (s[0] in "0123456789-") or s[-1]=='-':	return False
			for n in range(len(s)):
				if s[n].lower() not in "abcdefghijklmnopqrstuvwxyz0123456789-":	return False
			return True
		if label==None:	return None
		elif not label or type(label) not in [type(""),type([]),type(tuple([]))]:	return False
		if type(label)==type("") and __islabel(label):	return [label.strip().translate({'.':'-'})]
		for l in label:
			if type(l)!=type("") or not __islabel(l):	return False
		return [l.strip().translate({'.':'-'}) for l in list(label)]
	def isinstance(self, classname):
		if classname==OID:	return True
		else:	return False
	def relabel(self, relabel):
		relabel = self.__labelize(relabel)
		if relabel==False:	return False
		self.label = relabel
		return self.relabel
	def addlabel(self, label):
		label = self.__labelize(label)
		if label==False:	return False
		self.label.extend(label)
		return self.label
	def parent(self, relabel=None):
		if self.depth>1:
			if relabel:
				relabel = self.__labelize(relabel)
				if relabel==False:	relabel = None
			return OID(self.list[:-1], label=relabel)
		return None
	def sibling(self, arc, relabel=None):
		if not arc:	return None
		if relabel:
			relabel = self.__labelize(relabel)
			if relabel==False:	relabel = None
		if type(arc)==type(1):	return OID(self.list[:-1].append(arc), label=relabel)
		elif type(arc)==type("") and arc.isdigit():	return OID(self.list[:-1].append(int(arc)), label=relabel)
		else:	return None
	def child(self, arc, relabel=None):
		if not arc:	return None
		if relabel:
			relabel = self.__labelize(relabel)
			if relabel==False:	relabel = None
		if type(arc)==type(1):	return OID(self.list.append(arc), relabel=label)
		elif type(arc)==type("") and arc.isdigit():	return OID(self.list.append(int(arc)), relabel=label)
		else:	return None
def isOID(bytes):	return bool(OID(bytes))


class x509LogotypeExtension:
	def __init__(self):
		id_logo = OID(1,3,6,1,5,5,7,20,label="id-logo")
		self._otherLogoOIDs = frozenset([
			OID(id_logo,1,label="id-logo-loyalty"),
			OID(id_logo,2,label="id-logo-background"),
			OID(id_logo,3,label="id-logo-certImage")
		])
		self.extn = {	'community':[], 'issuer':None,'subject':None,'other':[]	}
	def Issuer(self, logo):
		if not logo:	self.extn['issuer'] = None
		elif not isinstance(logo,x509logotypeData):	return False
		self.extn['issuer'] = logo
		return True
	def Subject(self, logo):
		if not logo:	self.extn['subject'] = None
		elif not isinstance(logo,x509logotypeData):	return False
		self.extn['subject'] = logo
		return True
	def pushCommunity(self, logoarray):
		if isinstance(logoarray,x509logotypeData):
			self.extn['community'].append(logoarray)
		elif not logoarray or type(logoarray) not in [type([]),type(tuple([]))]:	return False
		for logo in logoarray:
			if not isinstance(logo,x509logotypeData):	return False
		for n in range(len(logoarray)):
			self.extn['community'].append( logoarray[n] )
		return True
	def pushOther(self, logoarray):
		if not logoarray or type(logoarray) not in [type([]),type(tuple([]))]:	return False
		for item in logoarray:
			if type(item) not in [type([]),type(tuple([]))] or len(item)!=2 or not isinstance(item[1],x509logotypeData):	return False
			if isOID(item[0]):	pass
			elif type(item[0])==type("") and item[0].lower() in self._otherLogosOIDs:	item[0] = OID(self._otherLogosOIDs[item[0].lower()])
			else:	return False
		for n in range(len(logoarray)):
			self.extn['other'].append(( OID(logoarray[n][0]),logoarray[n][1] ))
		return True
	def popCommunity(self, index=-1):
		return self.extn['community'].pop(index)
	def popOther(self, key=None):
		if key==None:	return self.extn['other'].popitem()
		elif key in self.extn['other'].keys(): return self.extn['other'].pop(key)
	def clearCommunity(self):	self.extn['community'] = []
	def clearOther(self):		self.extn['other'].clear()
	def struct(self):
		ret = {}
		if self.extn['community']:
			LL = []
			for m in range(len(self.extn['community'])):
				L = {0:{}}
				extn = self.extn['community'][m]
				for n in range(extn.len()):
					if extn.isimage(n):
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(extn.struct(n))
					elif extn.isaudio(n):
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(extn.struct(n))
				LL.append(L)
			ret[0] = LL
		for SubjIss in ['issuer','subject']:
			if self.extn[SubjIss]:
				L = {0:{}}
				for n in range(self.extn[SubjIss].len()):
					if self.extn[SubjIss].isimage(n):
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(self.extn[SubjIss].struct(n))
					elif self.extn[SubjIss].isaudio(n):
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(self.extn[SubjIss].struct(n))
				if SubjIss=='issuer':	ret[1] = L
				else:	ret[2] = L
		if self.extn['other']:
			LL = []
			for m in range(len(self.extn['other'])):
				L = {0:{}}
				extn = self.extn['other'][m][1]
				for n in range(extn.len()):
					if extn.isimage(n):
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(extn.struct(n))
					elif extn.isaudio(n):
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(extn.struct(n))
				LL.append( (self.extn['other'][m][0], L) )
			ret[3] = LL
		return ret
	def exportConfig(self, filename, section="logotypeExtn", append=True):
		import configparser
		def exportLogotypeDetails(cnf, d, section):
			#global cnf
			_hashAlg = {
				'sha1':OID((1,3,14,3,2,26),label="sha1"),
				'sha256':OID((2,16,840,1,101,3,4,2,1),label="sha256"),
				'sha512':OID((1,3,14,3,2,26),label="sha512"),
				'md5':OID((1,2,840,113549,2,5),label="md5")
			}
			cnf.add_section(section)
			for key in d.keys():
				if not d[key]:	continue
				elif key=='mediaType':	cnf.set(section, 'mediaType', "IA5STRING:%s"%d[key])
				elif key=='logotypeHash':
					cnf.set(section, 'logotypeHash', "SEQUENCE:%s.hash"%section)
					cnf.add_section(section+".hash")
					count=0
					for algoid in d[key].keys():
						cnf.set(section+".hash", 'digest.%d'%count, "SEQUENCE:%s.hash.%d"%(section,count))
						cnf.add_section(section+".hash.%d"%count)
						cnf.set(section+".hash.%d"%count, 'hashAlg', "SEQUENCE:%s"%repr(_hashAlg[algoid]))
						cnf.set(section+".hash.%d"%count, 'hashValue', "FORMAT:HEX,OCTETSTRING:%s"%d[key][algoid])
						count += 1
				elif key=='logotypeURI':
					cnf.set(section, 'logotypeURI', "SEQUENCE:%s.URI"%section)
					cnf.add_section(section+".URI")
					if type(d['logotypeURI'])==type(""):
						cnf.set(section+".URI", 'uri.0', "IA5STRING:%s"%d[key])
					else:
						for u in range(len(d[key])):
							cnf.set(section+".URI", 'uri.%d'%u, "IA5STRING:%s"%d[key][u])
				elif key in ['fileSize','playTime','channels']:
					cnf.set(section, key, "INTEGER:%d"%d[key])
				elif key=='sampleRate':	cnf.set(section, key, "EXPLICIT:3,INTEGER:%d"%d[key])
				elif key=='language':	cnf.set(section, key, "EXPLICIT:4,IA5STRING:%s"%d[key])
				#else:	cnf.set(section, key, d[key])
			return cnf
		commLogotypeInfo, commLogotypeData, commLogotypeImage, commLogotypeAudio, commLogotypeImageDetails, commLogotypeAudioDetails = [], [], [], [], [], []
		issuerLogotypeImage, issuerLogotypeAudio, issuerLogotypeImageDetails, issuerLogotypeAudioDetails = [], [], [], []
		subjectLogotypeImage, subjectLogotypeAudio, subjectLogotypeImageDetails, subjectLogotypeAudioDetails = [], [], [], []
		otherOtherLogotypeInfo, otherLogotypeInfo, otherLogotypeData, otherLogotypeImage, otherLogotypeAudio, otherLogotypeImageDetails, otherLogotypeAudioDetails = [], [], [], [], [], [], []
		logotypeOID = OID(1,3,6,1,5,5,7,1,12,label="logotype")
		logotypeASN1SEQ = "ASN1:SEQUENCE:" + section
		ext = self.struct()
		if not ext:	return False
		cnf = configparser.ConfigParser()
		cnf.add_section(section)
		if 0 in ext.keys():
			cnf.set(section, 'communityLogos', "EXPLICIT:0,SEQUENCE:communityLogos")
			cnf.add_section('communityLogos')
			for n in range(len(ext[0])):
				cnf.set('communityLogos', 'community.%d'%n, "IMPLICIT:0,SEQUENCE:community.%d.LogotypeInfo"%n)
				cnf.add_section('community.%d.LogotypeInfo'%n)
				cnf.set('community.%d.LogotypeInfo'%n, 'direct', "SEQUENCE:community.%d.LogotypeData"%n)
				cnf.add_section('community.%d.LogotypeData'%n)
				for img in range(len(ext[0][n][0])):
					cnf.set('community.%d.LogotypeData'%n, 'image.%d'%img, "SEQUENCE:community.%d.LogotypeImage.%d"%(n,img))
					cnf.add_section('community.%d.LogotypeImage.%d'%(n,img))
					cnf.set("community.%d.LogotypeImage.%d"%(n,img), 'imageDetails', "SEQUENCE:community.%d.LogotypeImage.%d.ImageDetails"%(n,img))
					cnf.add_section('community.%d.LogotypeImage.%d.ImageDetails'%(n,img))
					cnf = exportLogotypeDetails(cnf, ext[0][n][0][img][0], 'community.%d.LogotypeImage.%d.ImageDetails'%(n,img))
				for aud in range(len(ext[0][n][1])):
					cnf.set('community.%d.LogotypeData'%n, 'audio.%d'%aud, "SEQUENCE:community.%d.LogotypeAduio.%d"%(n,aud))
					cnf.add_section('community.%d.LogotypeAudio.%d'%(n,aud))
					cnf.set("community.%d.LogotypeAudio.%d"%(n,aud), 'audioDetails', "SEQUENCE:community.%d.LogotypeAudio.%d.AudioDetails"%(n,aud))
					cnf = exportLogotypeDetails(cnf, ext[0][n][1][aud][0], 'community.%d.LogotypeAudio.%d.AudioDetails'%(n,aud))
					if 1 in ext[0][n][1][aud].keys():
						cnf = exportLogotypeDetails(cnf, ext[0][n][1][aud][1], 'community.%d.LogotypeAudio.%d.AudioInfo'%(n,aud))
		if 1 in ext.keys():
			cnf.set(section, 'issuerLogo', "EXPLICIT:1,IMPLICIT:0,SEQUENCE:issuer.LogotypeInfo")
			cnf.add_section('issuer.LogotypeInfo')
			cnf.set('issuer.LogotypeInfo','direct',"SEQUENCE:issuer.LogotypeData")
			cnf.add_section('issuer.LogotypeData')
			for img in range(len(ext[1][0])):
				cnf.set('issuer.LogotypeData', 'image.%d'%img, "SEQUENCE:issuer.LogotypeImage.%d"%img)
				cnf.add_section('issuer.LogotypeImage.%d'%img)
				cnf.set('issuer.LogotypeImage.%d'%img, 'imageDetails', "SEQUENCE:issuer.LogotypeImage.%d.ImageDetails"%img)
				cnf = exportLogotypeDetails(cnf, ext[1][0][img][0], 'issuer.LogotypeImage.%d.ImageDetails'%img)
			if 1 in ext[1].keys():
				print(ext[1][1].keys())
				for aud in range(len(ext[1][1])):
					cnf.set('issuer.LogotypeData', 'audio.%d'%aud, "SEQUENCE:issuer.LogotypeAudio.%d"%aud)
					cnf.add_section('issuer.LogotypeAudio.%d'%aud)
					cnf.set('issuer.LogotypeAudio.%d'%aud, 'audioDetails', "SEQUENCE:issuer.LogotypeImage.%d.AudioDetails"%aud)
					cnf = exportLogotypeDetails(cnf, ext[1][1][aud][0], 'issuer.LogotypeImage.%d.AudioDetails'%aud)
					if 1 in ext[1][1][aud].keys():
						cnf = exportLogotypeDetails(cnf, ext[1][1][aud][1], 'issuer.LogotypeAudio.%d.AudioInfo'%aud)
		if 2 in ext.keys():
			cnf.set(section, 'subjectLogo', "EXPLICIT:1,IMPLICIT:0,SEQUENCE:subject.LogotypeInfo")
			cnf.add_section('subject.LogotypeInfo')
			cnf.set('subject.LogotypeInfo','direct',"SEQUENCE:subject.LogotypeData")
			cnf.add_section('subject.LogotypeData')
			for img in range(len(ext[2][0])):
				cnf.set('subject.LogotypeData', 'image.%d'%img, "SEQUENCE:subject.LogotypeImage.%d"%img)
				cnf.add_section('subject.LogotypeImage.%d'%img)
				cnf.set('subject.LogotypeImage.%d'%img, 'imageDetails', "SEQUENCE:subject.LogotypeImage.%d.ImageDetails"%img)
				cnf = exportLogotypeDetails(cnf, ext[2][0][img][0], 'subject.LogotypeImage.%d.ImageDetails'%img)
			for aud in range(len(ext[2][1])):
				cnf.set('subject.LogotypeData', 'audio.%d'%aud, "SEQUENCE:subject.LogotypeAudio.%d"%aud)
				cnf.add_section('issuer.LogotypeAudio.%d'%aud)
				cnf.set('subject.LogotypeAudio.%d'%aud, 'audioDetails', "SEQUENCE:subject.LogotypeImage.%d.AudioDetails"%aud)
				cnf = exportLogotypeDetails(cnf, ext[2][1][aud][0], 'subject.LogotypeImage.%d.AudioDetails'%aud)
				if 1 in ext[2][1][aud].keys():
					cnf = exportLogotypeDetails(cnf, ext[2][1][aud][1], 'subject.LogotypeAudio.%d.AudioInfo'%aud)
		if 3 in ext.keys():
			cnf.set(section, 'communityLogos', "EXPLICIT:3,SEQUENCE:otherLogos")
			cnf.add_section('otherLogos')
			for n in range(len(ext[3])):
				cnf.set('otherLogos', "other.%d"%n, "IMPLICIT:0,SEQUENCE:other.%d.OtherLogotypeInfo"%n)
				cnf.add_section('other.%d.OtherLogotypeInfo'%n)
				cnf.set('other.%d.OtherLogotypeInfo'%n, 'logotypeType', "OID:%s"%repr(ext[3][n][0]))
				cnf.set('other.%d.OtherLogotypeInfo'%n, 'info', "IMPLICIT:0,SEQUENCE:other.%d.LogotypeInfo"%n)
				cnf.add_section('other.%d.LogotypeInfo'%n)
				cns.set('other.%d.LogotypeInfo'%n, 'direct', "SEQUENCE:other.%d.LogotypeData"%n)
				cnf.add_section('other.%d.LogotypeData'%n)
				for img in range(len(ext[3][n][1][0])):
					cnf.set('other.%d.LogotypeData'%n, 'image.%d'%img, "SEQUENCE:community.%d.LogotypeImage.%d"%(n,img))
					cnf.add_section('community.%d.LogotypeImage.%d'%(n,img))
					cnf.set('community.%d.LogotypeImage.%d'%(n,img), 'imageDetails', "SEQUENCE:community.%d.LogotypeImage.%d.ImageDetails"%(n,img))
					cnf = exportLogotypeDetails(cnf, ext[3][n][1][0][img][0], 'community.%d.LogotypeImage.%d.ImageDetails'%(n,img))
				for aud in range(len(ext[3][n][1][1])):
					cnf.set('other.%d.LogotypeData'%n, 'audio.%d'%aud, "SEQUENCE:community.%d.LogotypeAudio.%d"%(n,aud))
					cnf.add_section('community.%d.LogotypeAudio.%d'%(n,aud))
					cnf.set('community.%d.LogotypeAudio.%d'%(n,aud), 'audioDetails', "SEQUENCE:community.%d.LogotypeAudio.%d.AudioDetails"%(n,aud))
					cnf = exportLogotypeDetails(cnf, ext[3][n][1][1][aud][0], 'community.%d.LogotypeAudio.%d.AudioDetails'%(n,aud))
					if 1 in ext[3][n][1][1][aud].keys():
						cnf = exportLogotypeDetails(cnf, ext[3][n][1][1][aud][1], 'other.%d.LogotypeAudio.%d.AudioInfo'%(n,aud))
		if append:	openstring = 'a'
		else:	openstring = 'w'
		with open(filename,openstring) as CNFfile:
			try:	cnf.write(CNFfile, space_around_delimiters=True)
			except:	return False
		return "%s\t=\t%s"%(repr(logotypeOID), logotypeASN1SEQ)
class x509logotypeData:
	def __init__(self, imagefile, imgformat=None, indirect=False, width=0,height=0,duration=None, language=None, channels=0, samplerate=0, hashtype="sha1"):
		#self.logos, self.isimage, self.isaudio = [], [], []
		self.logos = []
		if imagefile:
			self.add(imagefile,imgformat,indirect,width,height,duration, language, channels, samplerate,hashtype)
	def add(self, imagefile, imgformat=None, indirect=False, width=0,height=0,duration=None, language=None, channels=0, samplerate=0, hashtype="sha1"):
		self.logos.append( _x509logotypeDetails(imagefile,imgformat,indirect,width,height,duration,language,channels,samplerate,hashtype) )
#		try:	self.logos.append( _x509logotypeDetails(imagefile,imformat,indirect,width,height,duration,language,channels,samplerate,hashtype) )
#		except:	return False
		#self.isimage.append( self.logos[-1].isimage() )
		#self.isaudio.append( self.logos[-1].isaudio() )
		return True
	#def add(self, logo):
	#	if not isinstance(logo,_x509logotypeDetails):	return False
	#	self.logos.append(logo)
	#	self.isimage.append(logo.isimage())
	#	self.isaudio.append(logo.isaudio()) 
	#	return True
	def len(self):	return len(self.logos)
	def struct(self, num):	return self.logos[num].struct()
	def isimage(self,num):	return self.logos[num].isimage()
	def isaudio(self,num):	return self.logos[num].isaudio()
	def isdirect(self,num):	return self.logos[num].direct
	def mediaType(self,num):	return self.logos[num].mediaType
	def digest(self,num,hash=None):
		if num not in range(self.len()):	return False
		if not hash:	return self.logos[num].digest
		if hash not in self.logos[num].digest.keys():	return False
		return self.logos[num].digest[hash]
	def size(self,num):
		if self.isimage(num):	return (self.logos[num].width, self.logos[num].height)
		elif self.isaudio(num):	return self.logos[num].filesize
		else:	return False
	def URI(self,num):	return self.logos[n].URI
#	def digest(self,num,hashtype="sha1"):
#		if 
class _x509logotypeDetails:
	_mime = {
		'GIF'	: "image/gif",
		'JPG'	: "image/jpeg",
		'JPEG'	: "image/jpeg",
		'PNG'	: "image/png",
		'SVG'	: "image/svg+xml",
		'SVGZ'	: "image/svg+xml",
		'MP3'	: "audio/mpeg",
		'PDF'	: "application/pdf"
	}
	_hashAlg = {
		'sha1':OID((1,3,14,3,2,26),label="sha1"),
		'sha256':OID((2,16,840,1,101,3,4,2,1),label="sha256"),
		'sha512':OID((1,3,14,3,2,26),label="sha512"),
		'md5':OID((1,2,840,113549,2,5),label="md5")
	}
	def __init__(self, imagefile=None, imgformat=None, indirect=False, width=0,height=0, duration=None,language=None,channels=0,samplerate=0, hashtype="sha1"):
		"""Instantiates the class and optionally addsa document as logotype in the queue. Supported formats are GIF, JPEG, PNG, SVG (and SVGZ), PDF and MP3."""
#	def __init__(self):
		self.payload, self.direct, self.filesize, self.width, self.height, self.URI, self.playtime, self.lang, self.chN, self.rate, self.digest = None,None, 0, None, None, None, None, None, 0, 0, {}
		self.hashAlg = []
#	def addLogo(self, imagefile=None, imgformat=None, indirect=False, width=0,height=0, duration=None,language=None,channels=0,samplerate=0, hash="sha256"):
		multires = False
		if not imagefile or type(imagefile)!=type(""):	raise WrongArguments
		elif indirect:	self.URI = imagefile
		elif os.path.isfile(imagefile):
			try:
				open(imagefile,'rb').close()
				self.filesize = os.stat(imagefile).st_size
			except:	raise FileNotFoundOrUnaccessible
#		elif type(imagefile) in [type([]),type(tuple)]:
#			pass#
#		elif type(imagefile)==type({}):
#			for key in imagefile.keys():
#				if type(key) not in [type([]),type(tuple)] or len(key)!=2 or type(key[0])!=type(1) or type(key[1])!=type(1) or key[0]<=0 or key[1]<=0:	return -7
#				CODE FOR LOADING SEVERAL IMAGES WITH DIFFERENT RESOLUTIONS
		else:	raise FileNotFoundOrUnaccessible
		self.direct = not bool(indirect)
		if indirect and type(indirect)==type(""):	self.URI = indirect
		if not imgformat or type(imgformat)!=type(""):
			#if not self.direct:	raise WrongArguments
			ext = os.path.splitext(imagefile)[1]
			if ext and ext[0]=='.' and ext[1:].upper() in self._mime.keys():	imgformat = ext[1:].upper()
			else:	raise UnsupportedActualVsDeclaredFileFormat
		if type(hashtype)==type("") and hashtype.lower() in self._hashAlg.keys():
			self.hashAlg.append(hashtype.lower())
		elif type(hashtype) in [type([]),type(list([]))]:
			for s in hashtype:
				if type(s)==type("") and s.lower() in self._hashAlg.keys():
					self.hashAlg.append(s.lower())
				else:	raise WrongArguments
		else:	raise WrongArguments
		if "sha1" not in self.hashAlg:	self.hashAlg.append("sha1")
		if type(imgformat)!=type("") or imgformat.upper() not in self._mime.keys():	raise UnsupportedDeclaredFileFormatOrMIMEType
		else:	self.mediaType = self._mime[imgformat.upper()]
		if imgformat.upper()=="MP3":		## The only audio-logotype supported format
			if width!=0 or height!=0 or (language and type(language)!=type("")) or type(duration)!=type(1) or duration<=0 or type(samplerate)!=type(1) or samplerate<=0 or (channels not in [1,2,4]):	raise UnsupportedAudioMetadata
			if (not language) or type(language)!=type("") or not re.match(r"[A-Za-z0-9]{1,8}(\-[A-Za-z0-9]{1,8})?",language):	raise UnsupportedLanguage
			self.playtime, self.lang, self.chN, self.rate = duration, language, channels, samplerate
		else:									## The logotype is an image format (generic routines). Inser optional resolution/bit-depth validation code.
			if type(width)!=type(1) or type(height)!=type(1) or height<0 or width<0:	raise UnsupportedPictureMetadata
			self.width, self.height = width, height
		if imgformat.upper()!="MP3":
			if language==None or (type(language)==type("") and re.match(r"[A-Za-z0-9]{1,8}(\-[A-Za-z0-9]{1,8})?",language)):	self.language = language
			else:	raise UnsupportedLanguage
		if imgformat.upper()=="SVG":
			import mmap
			with open(imagefile,'r') as file:
				_svg = mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ)
				if _svg.find("<script")!=-1:	raise UnsupportedDeclaredFileFormatOrMIMEType
				_svg.close()
			####	Potentially add SVG Tiny 1.2 parser that also checks lack of external references
		if imgformat.upper()=="SVG":
			import tempfile
			import gzip
			import lxml
			#import zipfile
			try:	tmp = tempfile.TemporaryFile()
			except:	raise TemporaryFileWriteError
			c14n = io.StringIO.StringIO()
			imagebuf = open(imagefile,'rb')
			_svg = mmap.mmap(imagebuf.fileno(),0,access=mmap.ACCESS_READ)
			if _svg.find("<script")!=-1:	raise UnsupportedDeclaredFileFormatOrMIMEType
			_svg.close()
			imagebuf.seek(0)
			try:
				_et = lxml.etree.parse(imagebuf)
				_et.write_c14n(c14n,exclusive=1,with_comments=0)
			except:	raise UnsupportedDeclaredFileFormatOrMIMEType
			imagebuf.close()
			try:
				tmp.write(c14n.getvalue())
				tmp.seek(0)
				imagebuf = io.BytesIO(gzip.compress(tmp.read()))
				#zipbuf = zipfile.ZipFile(imagebuf,'w',zipfile.ZIP_DEFLATED)
				#zipbuf.writestr(os.path.basename(imagefile),tmp.read())
				#zipbuf.close()
				tmp.seek(0)
				del c14n
			except:	raise TemporaryFileWriteError
			#imagebuf.seek(0)
			self.payload = base64.b64encode(imagebuf.getbuffer())
		elif imgformat.upper()=="SVGZ":
			import gzip
			import lxml
			if not self._isGZIPfile(open(imagefile,'rb').read(10).decode()):	raise UnsupportedActualVsDeclaredFileFormat
			with gzip.open(imagefile,'rb') as gz:	imagebuf = gz.read()
			c14n = io.StringIO.StringIO()
			try:	
				_et = lxml.etree.parse(imagebuf)
				_et.write_c14n(c14n)
			except:	raise UnsupportedDeclaredFileFormatOrMIMEType
			self.payload = base64.b64encode(c14n.read())
			del c14n
		elif imgformat.upper()=="SVG+ZIP":
			imagebuf = open(imagefile,'rb')
			if not self._isZIPfile(imagebuf.read(32).decode()):	raise UnsupportedActualVsDeclaredFileFormat
			imagebuf.seek(0)
			self.payload = base64.b64encode(imagebuf.read()).decode()
		else:
			imagebuf = open(imagefile,'rb')
			imgheader = imagebuf.read(128)
			ret = self._isValidFormat(imgheader)
			imagebuf.seek(0)
			self.payload = base64.b64encode(imagebuf.read()).decode()
			imagebuf.seek(0)
		if imgformat.upper()!="SVGZ":	imagebuf.seek(0)
		for algtype in self.hashAlg:
			if algtype=="sha256":	blkhash = hashlib.sha256()
			elif algtype=="sha512":	blkhash = hashlib.sha512()
			elif algtype=="sha1":	blkhash = hashlib.sha1()
			elif algtype=="md5":	blkhash = hashlib.md5()
			else:	raise UnsupportedHashingAlgorithm
			if imgformat.upper()=="SVGZ":
				blkhash.update(tmp.read())
				tmp.seek(0)
			else:	blkhash.update(imagebuf.read())
			self.digest[ self._hashAlg[algtype] ] = blkhash.hexdigest()
			del blkhash
		if imgformat.upper()=="SVGZ":	tmp.close()
		imagebuf.close()
		if self.direct and not self.URI:
			self.URI = "data:" + self.mediaType + ";base64," + self.payload
	def isimage(self):	return self.mediaType.startswith("image/") or self.mediaType=="application/pdf"
	def isaudio(self):	return self.mediaType.startswith("audio/")
	def struct(self):
		digesta = {}
		for key in self.digest.keys():
			if key in self._hashAlg.values():
				for hashname in self._hashAlg.keys():
					if self._hashAlg[hashname]==key:
						digesta[hashname] = self.digest[key]
						break
			elif key in self._hashAlg.keys():	digesta[key] = self.digest[key]
		if self.isaudio():
			return ({		## logotypeDetail structure
				'mediaType':	self.mediaType,
				'logotypeHash':	digesta,
				'logotypeURI':	self.URI,
			},{		## logotypeAudioInfo structure
				'filesize':	self.filesize,
				'playTime':	self.playtime,
				'channels':	self.chN,
				'sampleRate':self.rate,
				'language':	self.lang
			})
		return {
			'mediaType':	self.mediaType,
			'logotypeHash':	digesta,
			'logotypeURI':	self.URI,
		}
	def _isValidFormat(self,payload):
		import struct
		def _isPDFfile(payload):
			"""Tests whether a payload begins with a valid PDF fileW's magic number."""
			if len(payload)<32 or payload[:5]==b"%PDF-" and payload[5].isdigit():	return True
			return False
		def _isPNGfile(payload):
			"""Tests whether a payload begins with a valid PNG image's magic number."""
			if len(payload)<128 or payload[:8]!=b"\x89PNG\r\n\x1A\n" or payload[12:16]!=b"IHDR":	return False
			raw_info = struct.unpack(">LL", payload[16:24])
			return (raw_info[0],raw_info[1])
		def _isJPGfile(payload):
			"""Tests whether a payload begins with a valid JPEG/JFIF image's magic number."""
			if len(payload)<128 or payload[0:4]!=b"\xFF\xD8\xFF\xE0" or payload[6:11]!=b"JFIF\x00":	return False
			k = 11
			while k<1014:
				if payload[k:k+2]=='\xFF\xC0':	break
				k +=1
			else:	return -7
			raw_info = struct.unpack(">HH", payload[k+5:k+9])
			if raw_info[0]==474 and ord(raw_info[1])<=1 and 1<=ord(raw_info[2])<=2 and 1<=raw_info[3]<=3:	return (raw_info[4],raw_info[5])
			else:	return (raw_info[1], raw_info[0])
		def _isGIFfile(payload):
			"""Tests whether a payload begins with a valid CompuServe GIF image's magic number."""
			if len(payload)<16 or payload[0:6] not in [b"GIF87a",b"GIF89a"]:	return False
			raw_info = struct.unpack("<HH", payload[6:10])
			return (raw_info[0],raw_info[1])
		def _isMP3file(payload):
			"""Tests whether a payload begins with a valid MP3 audio file's magic number."""
			if len(payload)<128 or payload[0:2] not in [b"\xFF\xFB",b"\xFF\xF3",b"\xFF\xF2"]:	return False
			return True
		#payload	direct	filesize	width	height	URI	playtime	lang	chN	rate	digest
		if self.isimage():
			if self.mediaType=="application/pdf":	return _isPDFfile(payload)
			elif self.mediaType=="image/gif":	res = _isGIFfile(payload)
			elif self.mediaType=="image/png":	res = _isPNGfile(payload)
			elif self.mediaType=="image/jpeg":	res = _isJPGfile(payload)
			elif self.mediaType=="image/svg+xml":	return True
			else:	return False
			if self.width and self.height and res==(self.width,self.height):	return True
			elif res and ((not self.width) or (not self.height)):
				(self.width,self.height) = res
				return True
			return False
		elif self.isaudio():
			if self.mediaType=="audio/mpeg":	return _isMP3file(payload)
			else:	return False
		return False
	def _isGZIPfile(payload):
		"""Tests whether a payload begins with a valid gzip file's magic number."""
		if len(payload)<10 or payload[0:2]!=b"\x1F\x8B" or payload[2]!=b'\x08':	return False
		return True
	def _isZIPfile(payload):
		"""Tests whether a payload begins with a valid ZIP file's magic number."""
		if len(payload)<32 or payload[0:2]!=b"PK" or payload[2:4] not in [b"\x03\x04"]:	return False
		return True



###	Custom Exceptions
class FileNotFoundOrUnaccessible(Exception):	pass	# USED
class WrongArguments(Exception):	pass					# USED
class UnsupportedFileFormat(Exception):	pass
class UnsupportedCodec(UnsupportedFileFormat):	pass
class UnsupportedMetadata(UnsupportedFileFormat):	pass
class UnsupportedContainerFormat(UnsupportedMetadata):	pass
class UnsupportedPackageFormat(UnsupportedMetadata):	pass
class UnsupportedCharactersVsNamingConventions(Exception):	pass
class UnsupportedActualVsDeclaredFileFormat(UnsupportedFileFormat):	pass	# USED
class UnsupportedDeclaredFileFormatOrMIMEType(UnsupportedActualVsDeclaredFileFormat):	pass	# USED
class UnsupportedAlgorithm(Exception):	pass
class UnsupportedSignatureAlgorithm(UnsupportedAlgorithm):	pass
class UnsupportedHashingAlgorithm(UnsupportedAlgorithm):	pass	# USED
class UnsupportedDigest(UnsupportedHashingAlgorithm):	pass
class UnsupportedLanguage(UnsupportedMetadata):	pass	# USED
class UnsupportedPictureMetadata(UnsupportedMetadata):	pass	# USED
class UnsupportedAudioMetadata(UnsupportedMetadata):	pass	# USED
class TemporaryFileWriteError(Exception):	pass	# USED


def importOIDs(filename, db=None):
	if not db or type(db)!=type({}):	db = {}
	labelre = re.compile(r"[a-zA-Z][a-z_A-Z0-9]*[a-zA-Z0-9]",flags=re.ASCII)
	oidre = re.compile(r"(?P<arc>\d+)|(\$\{(?P<arc>[a-zA-Z][a-z_A-Z0-9]*[a-zA-Z0-9])\})",flags=re.ASCII)
	lines = open(filename,'r').readlines()
	lines = [lines[n].strip().split() for n in range(len(lines)) if lines[n].strip() and not lines[n].strip().startswith('#')]
	for n in range(len(lines)):
		if len(lines[n])!=3 or lines[n][1]!='=' or not labelre.match(lines[n][0]):
			print("Invalid line start for OID #%d"%n)
			return False
		bites = map(oidre.match, lines[n][2].split('.'))
		if None in bites:
			print("Invalid OID on line #%d"%n)
			return False
		db[lines[n][0]] = list(map(oidre.match, lines[n][2].split('.')))
	print(db)
	return db


if __name__ == "__main__": main()
