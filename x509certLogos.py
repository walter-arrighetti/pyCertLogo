#!/usr/bin/python
##########################################################
#  x509certLogos  0.1                                    #
#                                                        #
#    conforms with:                                      #
#         RFC-3709: Logotypes in X.509 Certificates      #
#         RFC-6170: Cerificate Image                     #
#                                                        #
#    Copyright (C) 2023 Walter Arrighetti, Ph.D.         #
#    All Rights Reserved.                                #
##########################################################
VERSION = "0.1"
## This version of the spec does NOT check:
##   * if the SVG logo conforms with W3C's SVG Tiny 1.2 specs
##   * if the PNG logo conforms with ISO-15948 specs
##   * if the PDF logo conforms with PDF/A specs from ISO 32000
##   * if the language tags for audio logos conforms with RFC-3066
import tempfile
import hashlib
import base64
import zip
import os
import io
import re

class OID:
	def __init__(self, oid0, oid1=None):
		if oid0 and type(oid0)==type(""):	# Parse as a string x.y.z....
			oid0 = oid0.split('.')
		elif oid0 and type(oid0) in [type([]),type(list([]))]:	# Parse as a tuple/list [x,y,z,...] or (x,y,z,...)
			oid0 = list(oid0)
		elif oid0.isinstance(OID):	oid0 = oid0.str.split('.')
		else:	return False
		if oid1:
			if type(oid1)==type(""):	oid1 = oid1.split('.')
			elif type(oid1) in [type([]),type(list([]))]:	oid1 = list(oid1)
			elif oid1.isinstance(OID):	oid1 = oid1.str.split('.')
			else:	return False
			oid0 += oid1
		try:	oid0 = list(map(int,oid0))
		except:	return False
		self.list, self.depth, self.tuple, self.str = oid0, len(oid0), tuple(oid0), '.'.join(list(map(str,oid0)))
		return self.oid
	#def str(self):	return self.oid.join('.')
def isOID(bytes):	return bool(OID(bytes))

class x509LogoTypeExtn:
	def __init__(self):
		id_logo = OID(1,3,6,1,5,5,7,20)
		self._otherLogosOIDs = {
			"loyalty":OID(id_logo,1),	"id-logo-loyalty":OID(id_logo,1),
			"background":OID(id_logo,2),	"id-logo-background":OID(id_logo,2),
			"certimage":OID(id_logo,3)	"id-logo-certimage":OID(id_logo,3)
		}
		self.extn = {	'community':[], 'issuer':None,'subject':None,'other':[]	}
	def addIssuerLogo(self, logo):
		if not logo.isinstance(x509logotypeData):	return False
		self.extn['issuer'] = logo
	def addSubjectLogo(self, logo):
		if not logo.isinstance(x509logotypeData):	return False
		self.extn['subject'] = logo
	def addCommunityLogos(self, logoarray):
		if logoarray.isinstance(x509logotypeData):
			self.extn['community'].append(logoarray)
		elif not logoarray or type(logoarray) not in [type([]),type(tuple([]))]:	return False
		for logo in logoarray if not logo.isinstance(x509logotypeData):	return False
		for n in range(len(logoarray)):
			self.extn['community'].append( logoarray[n] )
		return True
	def addOtherLogos(self, logoarray):
		if not logoarray or type(logoarray) not in [type([]),type(tuple([]))]:	return False
		for item in logoarray:
			if type(item) not in [type([]),type(tuple([]))] or len(item)!=2 or not item[1].isinstance(x509logotypeData):	return False
			if isOID(item[0]):	pass
			elif type(item[0])==type("") and item[0].lower() in self._otherLogosOIDs):	item[0] = OID(self._otherLogosOIDs[item[0].lower()])
			else:	return False
		for n in range(len(logoarray)):
			self.extn['other'].append(( OID(logoarray[n][0]),logoarray[n][1] ))
		return True
	def struct(self):
		ret = {}
		if self.extn['community']:
			LL = []
			for m in range(len(self.extn['community'])):
				L = {0:[]}
				extn = self.extn['community'][m]
				for n in range(extn.len()):
					if extn[n].isimage():
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(extn[n].struct())
					elif extn[n].isaudio():
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(extn[n].struct())
				LL.append(L)
			ret[0] = LL
		for SubjIss in ['issuer','subject']:
			if self.extn[SubjIss]:
				L = {0:[]}
				for n in range(self.extn[SubjIss].len()):
					if self.extn[SubjIss][n].isimage():
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(self.extn[SubjIss][n].struct())
					elif self.extn[SubjIss][n].isaudio():
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(self.extn[SubjIss][n].struct())
				if SubjIss=='issuer':	ret[1] = L
				else:	ret[2] = L
		if self.extn['other']:
			LL = []
			for m in range(len(self.extn['other'])):
				L = {0:[]}
				extn = self.extn['other'][m][1]
				for n in range(self.extn['other'][m].len()):
					if self.extn['other'][m][n].isimage():
						if 0 not in L[0].keys():	L[0][0] = []
						L[0][0].append(self.extn['other'][m][n].struct())
					elif self.extn['other'][m][n].isaudio():
						if 1 not in L[0].keys():	L[0][1] = []
						L[0][1].append(self.extn['other'][m][n].struct())
				LL.append( (self.extn['other'][m][0], L) )
			ret[3] = LL
		return ret
	def exportOpenSSLconfig(self, filename, section="logotypeExtn", append=True):
		import configparser
		commLogotypeInfo, commLogotypeData, commLogotypeImage, commLogotypeAudio, commLogotypeImageDetails, commLogotypeAudioDetails = [], [], [], [], [], []
		issuerLogotypeImage, issuerLogotypeAudio, issuerLogotypeImageDetails, issuerLogotypeAudioDetails = [], [], [], [], [], []
		subjectLogotypeImage, subjectLogotypeAudio, subjectLogotypeImageDetails, subjectLogotypeAudioDetails = [], [], [], [], [], []
		otherOtherLogotypeInfo, otherLogotypeInfo, otherLogotypeData, otherLogotypeImage, otherLogotypeAudio, otherLogotypeImageDetails, otherLogotypeAudioDetails = [], [], [], [], [], [], []
		logotypeOID = OID((1,3,6,1,5,5,7,1,12))
		logotypeASN1SEQ = "ASN1:SEQUENCE:" + section
		ext = self.struct()
		if not ext:	return False
		cnf = configparser.ConfigParser()
		logotypeExtn = cnf[section]
		if 0 in ext.keys():
			logotypeExtn['communityLogos'] = "EXPLICIT:0,SEQUENCE:communityLogos"
			communityLogos = cnf['communityLogos']
			for n in range(len(ext[0)):
				communityLogos["community.%d"%n] = "IMPLICIT:0,SEQUENCE:community.%d.LogotypeInfo"%n
				commLogotypeInfo.append( cnf['community.%d.LogotypeInfo'%n] )
				commLogotypeInfo[-1]['direct'] = "SEQUENCE:community.%d.LogotypeData"%n
				commLogotypeData.append( cnf['community.%d.LogotypeData'%n] )
				for img in len(ext[0][n][0]):
					commLogotypeData[-1]['image.%d'%img] = "SEQUENCE:community.%d.LogotypeImage.%d"%(n,img)
					commLogotypeImage.append( cnf['community.%d.LogotypeImage.%d'%(n,img)] )
					commLogotypeImage[-1]['imageDetails'] = cnf['community.%d.LogotypeImage.%d.ImageDetails'%(n,img)]
					commLogotypeImageDetails.append( cnf['community.%d.LogotypeImage.%d.ImageDetails'%(n,img)] )
					for key in ext[0][n][0][img][0].keys():
						commLogotypeImageDetails[-1][key] = ext[0][n][0][img][0][key]
				for aud in len(ext[0][n][1]):
					commLogotypeData[-1]['audio.%d'%aud] = "SEQUENCE:community.%d.LogotypeAudio.%d"%(n,aud)
					commLogotypeAudio.append( cnf['community.%d.LogotypeAudio.%d'%(n,aud)] )
					commLogotypeAudio[-1]['imageDetails'] = cnf['community.%d.LogotypeAudio.%d.AudioDetails'%(n,aud)]
					commLogotypeAudioDetails.append( cnf['community.%d.LogotypeAudio.%d.AudioDetails'%(n,aud)] )
					for key in ext[0][n][1][aud][0].keys():
						commLogotypeImageDetails[-1][key] = ext[0][n][1][aud][0][key]
					if 1 in ext[0][n][1][aud].keys():
						commLogotypeAudioInfos.append( cnf['community.%d.LogotypeAudio.%d.AudioInfo'%(n,aud)] )		# THIS IS OPTIONAL
						for key in ext[0][n][1][aud][1].keys():
							commLogotypeImageDetails[-1][key] = ext[0][n][1][aud][1][key]
		if 1 in ext.keys():
			logotypeExtn['issuerLogo'] = "EXPLICIT:1,IMPLICIT:0,SEQUENCE:issuerLogotypeInfo"
			issuerLogotypeInfo = cnf['issuer.LogotypeInfo'] )
			issuerLogotypeInfo['direct'] = "SEQUENCE:issuer.LogotypeData"
			issuerLogotypeData = cnf['issuer.LogotypeData'] )
			for img in len(ext[1][0]):
				issuerLogotypeData[-1]['image.%d'%img] = "SEQUENCE:issuer.LogotypeImage.%d"%img
				issuerLogotypeImage.append( cnf['issuer.LogotypeImage.%d'%img] )
				issuerLogotypeImage[-1]['imageDetails'] = cnf['issuer.LogotypeImage.%d.ImageDetails'%img]
				issuerLogotypeImageDetails.append( cnf['issuer.LogotypeImage.%d.ImageDetails'%img] )
				for key in ext[1][0][img][0].keys():
					issuerLogotypeImageDetails[-1][key] = ext[1][0][img][0][key]
			for aud in len(ext[1][1]):
				issuerLogotypeData[-1]['audio.%d'%aud] = "SEQUENCE:issuer.LogotypeAudio.%d"%aud
				issuerLogotypeAudio.append( cnf['issuer.LogotypeAudio.%d'%(n,aud)] )
				issuerLogotypeAudio[-1]['imageDetails'] = cnf['issuer.LogotypeAudio.%d.AudioDetails'%aud]
				issuerLogotypeAudioDetails.append( cnf['issuer.LogotypeAudio.%d.AudioDetails'%aud] )
				for key in ext[1][1][aud][0].keys():
					issuerLogotypeImageDetails[-1][key] = ext[1][1][aud][0][key]
				if 1 in ext[1][1][aud].keys():
					issuerLogotypeAudioInfos.append( cnf['issuer.LogotypeAudio.%d.AudioInfo'%aud] )		# THIS IS OPTIONAL
					for key in ext[1][1][aud][1].keys():
						issuerLogotypeImageDetails[-1][key] = ext[1][1][aud][1][key]
		if 2 in ext.keys():
			logotypeExtn['subjectLogo'] = "EXPLICIT:2,IMPLICIT:0,SEQUENCE:subjectLogo"
			subjectLogotypeInfo = cnf['subject.LogotypeInfo'] )
			subjectLogotypeInfo['direct'] = "SEQUENCE:subject.LogotypeData"
			subjectLogotypeData = cnf['subject.LogotypeData'] )
			for img in len(ext[2][0]):
				subjectLogotypeData[-1]['image.%d'%img] = "SEQUENCE:subject.LogotypeImage.%d"%img
				subjectLogotypeImage.append( cnf['subject.LogotypeImage.%d'%img] )
				subjectLogotypeImage[-1]['imageDetails'] = cnf['subject.LogotypeImage.%d.ImageDetails'%img]
				subjectLogotypeImageDetails.append( cnf['subject.LogotypeImage.%d.ImageDetails'%img] )
				for key in ext[2][0][img][0].keys():
					issuerLogotypeImageDetails[-1][key] = ext[2][0][img][0][key]
			for aud in len(ext[2][1]):
				subjectLogotypeData[-1]['audio.%d'%aud] = "SEQUENCE:subject.LogotypeAudio.%d"%aud
				subjectLogotypeAudio.append( cnf['subject.LogotypeAudio.%d'%(n,aud)] )
				subjectLogotypeAudio[-1]['imageDetails'] = cnf['subject.LogotypeAudio.%d.AudioDetails'%aud]
				subjectLogotypeAudioDetails.append( cnf['subject.LogotypeAudio.%d.AudioDetails'%aud] )
				for key in ext[2][1][aud][0].keys():
					subjectLogotypeImageDetails[-1][key] = ext[2][1][aud][0][key]
				if 1 in ext[2][1][aud].keys():
					subjectLogotypeAudioInfos.append( cnf['subject.LogotypeAudio.%d.AudioInfo'%aud] )		# THIS IS OPTIONAL
					for key in ext[2][1][aud][1].keys():
						subjectLogotypeImageDetails[-1][key] = ext[2][1][aud][1][key]
		if 3 in ext.keys():
			logotypeExtn['communityLogos'] = "EXPLICIT:3,SEQUENCE:otherLogos"
			otherLogos = cnf['otherLogos']
			for n in range(len(ext[3])):
				otherLogos["other.%d"%n] = "IMPLICIT:0,SEQUENCE:other.%d.OtherLogotypeInfo"%n
				otherOtherLogotypeInfo.append( cnf['other.%d.OtherLogotypeInfo'%n] )
				otherOtherLogotypeInfo[-1]['logotypeType'] = "OID:%s"%ext[3][n][0].str
				otherOtherLogotypeInfo[-1]['info'] = "IMPLICIT:0,SEQUENCE:other.%d.LogotypeInfo"%n
				otherLogotypeInfo.append( cnf['other.%d.LogotypeInfo'%n] )
				otherLogotypeInfo[-1]['direct'] = "SEQUENCE:other.%d.LogotypeData"%n
				otherLogotypeData.append( cnf['other.%d.LogotypeData'%n] )
				for img in len(ext[3][n][1][0]):
					otherLogotypeData[-1]['image.%d'%img] = "SEQUENCE:community.%d.LogotypeImage.%d"%(n,img)
					otherLogotypeImage.append( cnf['community.%d.LogotypeImage.%d'%(n,img)] )
					otherLogotypeImage[-1]['imageDetails'] = cnf['community.%d.LogotypeImage.%d.ImageDetails'%(n,img)]
					otherLogotypeImageDetails.append( cnf['community.%d.LogotypeImage.%d.ImageDetails'%(n,img)] )
					for key in ext[3][n][1][0][img][0].keys():
						otherLogotypeImageDetails[-1][key] = ext[3][n][1][0][img][0][key]
				for aud in len(ext[3][n][1][1]):
					otherLogotypeData[-1]['audio.%d'%aud] = "SEQUENCE:other.%d.LogotypeAudio.%d"%(n,aud)
					otherLogotypeAudio.append( cnf['other.%d.LogotypeAudio.%d'%(n,aud)] )
					otherLogotypeAudio[-1]['imageDetails'] = cnf['other.%d.LogotypeAudio.%d.AudioDetails'%(n,aud)]
					otherLogotypeAudioDetails.append( cnf['other.%d.LogotypeAudio.%d.AudioDetails'%(n,aud)] )
					for key in ext[3][n][1][1][aud][0].keys():
						otherLogotypeImageDetails[-1][key] = ext[3][n][1][1][aud][0][key]
					if 1 in ext[3][n][1][1][aud].keys():
						otherLogotypeAudioInfos.append( cnf['other.%d.LogotypeAudio.%d.AudioInfo'%(n,aud)] )		# THIS IS OPTIONAL
						for key in ext[3][n][1][1][aud][1].keys():
							otherLogotypeImageDetails[-1][key] = ext[3][n][1][1][aud][1][key]
		if append:	openstring = 'a'
		else:	openstring = 'w'
		with open(filename,configstring) as CNFfile:
			try:	cnf.write(CNFfile, space_around_delimiters=True)
			except:	return False
		return "%s\t=\t%s"%(logotypeOID.str, logotypeASN1SEQ)
class x509logotypeData:
	def __init__(self):
		self.logos, self.isimage, self.isaudio = [], [], []
	def add(self, logo):
		if not logo.isinstance(x509logotypeDetails):	return False
		self.logos.append(logo)
	def len(self):	return len(self.logos)
	def struct(self, num):	return self.logos[n].struct()
	def isimage(self,num):	return self.logos[n].isimage()
	def isaudio(self,num):	return self.logos[n].isaudio()
	def mediaType(self,num):	return self.logos[n].mediaType
	def size(self,num):
		if self.isimage(num):	return (self.logos[n].width, self.logos[n].height)
		elif self.isaudio(num):	return self.logos[n].filesize
		else:	return False
	def URI(self,num):	return self.logos[n].URI
#	def digest(self,num,hash="sha1"):
#		if 
class x509logotypeDetails:
	def __init__(self):
		self.payload, self.direct, self.filesize, self.width, self.height, self.URI, self.playtime, self.lang, self.chN, self.rate, self.digest = None,None, 0, None, None, [], None, None, 0, 0, {}
		self._mime = {
			'GIF'	: "image/gif",
			'JPG'	: "image/jpeg",
			'JPEG'	: "image/jpeg",
			'PNG'	: "image/png",
			'SVG'	: "image/svg+xml",
			'SVGZ'	: "image/svg+xml",
			'MP3'	: "audio/mpeg",
			'PDF'	: "application/pdf"
		}
		self._hashAlg, hashAlg = {
			'sha1':OID(()),
			'sha256':OID((2,16,840,1,101,3,4,2,1)),
			'sha512':OID((1.3,14,3,2,26)),
			'md5':OID(())
		}, []
	def addLogo(self, imagefile, imgformat, indirect=False, width=0,height=0,duration=None, language=None, channels=0, samplerate=0, hash="sha256"):
	"""
		Adds a document as logotype in the queue. Supported formats are GIF, JPEG, PNG, SVG (and SVGZ), PDF and MP3. Returns:
		 0		OK
		-1		File not found or not accessible
		-2		Erroneous formatting of arguments
		-3		Unsupported file format vs declared format
		-4		Unspported declared file format / MIME type
		-5		Unsupported hash algorithm
		-6		Unsupported declared language
		-7		Unsupported picture metadata
		-8		Unsupported audio metadata
		-9		Unable to write temporary files
	"""
		multires = False
		if type(imagefile)==type("") and os.path.isfile(imagefile):
			try:
				open(filesize,'rb').close()
				self.filesize = os.stat(imagefile).st_size
			except:	return -1
		elif type(imagefile) in [type([]),type(tuple)]:
			pass#
#		elif type(imagefile)==type({}):
#			for key in imagefile.keys():
#				if type(key) not in [type([]),type(tuple)] or len(key)!=2 or type(key[0])!=type(1) or type(key[1])!=type(1) or key[0]<=0 or key[1]<=0:	return -7
#				CODE FOR LOADING SEVERAL IMAGES WITH DIFFERENT RESOLUTIONS
		else:	return -1
		if type(indirect)==type("") and indirect:
			self.URI.append(indirect)
		elif type(indirect)==type(True):	pass
		else:	return -2
		self.direct = not bool(indirect)
		if type(hash)==type("") and hash.lower() in self._hashAlg.keys():
			hashAlg.append(hash.lower())
		elif type(hash) in [type([]),type(list([]))]:
			for s in hash:
				if type(s)==type("") and s.lower() in self._hashAlg.keys():
					hashAlg.append(s.lower())
				else:	return -2
		else:	return -2
		if "sha1" not in hashAlg:	hashAlg.append("sha1")
		if type(imgformat)!=type("") or imgformat.upper() not in self._mime.keys():	return -4
		else:	self.mediaType = self._mime[imgformat.upper()]
		if imgformat.upper()=="MP3":		## The only audio-logotype supported format
			if width!=0 or height!=0 or (language and type(language)!=type("")) or type(duration)!=type(1) or duration<=0 or type(samplerate)!=type(1) or samplerate<=0 or (channels not in [1,2,4]):	return -8
			if (not language) or type(language)!=type("") or not re.match(r"[A-Za-z0-9]{1,8}(\-[A-Za-z0-9]{1,8})?",language):	return -6
			self.playtime, self.lang, self.chN, self.rate = duration, language, channels, samplerate
		elif imgformat.upper()=="PDF":		## Insert (currently lacking) PDF and PDF/A validation routines
			pass
		else:									## The logotype is an image format (generic routines). Inser optional resolution/bit-depth validation code.
			if type(width)!=type(1) or type(height)!=type(1) or height<=0 or width<=0:	return -7
			self.width, self.height = height, width
		if imgformat.upper()!="MP3":
			if language==None or (type(language)==type("") and re.match(r"[A-Za-z0-9]{1,8}(\-[A-Za-z0-9]{1,8})?",language)):	self.language = language
			else:	return -6
		if imgformat.upper() in ["SVG","SVGZ"]:
			import mmap
			with open(imagefile,'r') as file:
				_svg = mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ):
				if _svg.find("<script")!=-1:	return -4
				_svg.close()
			####	Potentially add SVG Tiny 1.2 parser that also checks lack of external references
		if imgformat.upper()=="SVG":
			import zipfile
			import lxml
			try:	tmp = tempfile.TemporaryFile()
			except:	return -9
			c14n = io.StringIO.StringIO()
			imagebuf = io.BytesIO()
			try:	
				_et = lxml.etree.parse(imagefile)
				_et.write_c14n(c14n)
			except:	return -4
			try:
				tmp.write(c14n.getvalue())
				tmp.seek(0)
				zipbuf = zipfile.ZipFile(imagebuf,'w',zipfile.ZIP_DEFLATED)
			#zipbuf.writestr(os.path.basename(imagefile),open(imagefile,'rb').read()) 
				zipbuf.writestr(os.path.basename(imagefile),tmp.read())
				zipbuf.close()
				tmp.close()
				del c14n
			except:	return -9
			imagebuf.seek(0)
			self.payload = base64.b64encode(imagebuf.getbuffer())
		else:
			imagebuf = open(imagefile,'rb')
			self.payload = base64.b64encode(imagebuf.read())
		imagebuf.seek(0)
		for algtype in hashAlg:
			if algtype=="sha256":	blkhash = hashlib.sha256()
			elif algtype=="sha512":	blkhash = hashlib.sha512()
			elif algtype=="sha1":	blkhash = hashlib.sha1()
			elif algtype=="md5":	blkhash = hashlib.md5()
			if imgformat.upper()=="SVG":
				self.digest[ self._hashAlg[algtype] ] = blkhash.update(imagebuf.getbuffer()).hexdigest()
			else:
				self.digest[ self._hashAlg[algtype] ] = blkhash.update(imagebuf.read()).hexdigest()
		imagebuf.close()
		if not self.indirect:
			self.URI.append("data:" + self.mediaType + ";base64," + self.payload)
		return 0
	def isimage(self):	return self.mediaType.startswith("image/") or self.mediaType=="application/pdf"
	def isaudio(self):	return self.mediaType.startswith("audio/")
	def struct(self):
		if self.isaudio():
			return ({		## logotypeDetail structure
				'mediaType':	self.mediaType,
				'logotypeHash':	self.digest,
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
			'logotypeHash':	self.digest,
			'logotypeURI':	self.URI,
		}


	
