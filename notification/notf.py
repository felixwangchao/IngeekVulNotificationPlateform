#!/usr/bin
# -*- coding: utf-8 -*-

import os
import sys
import time
import codecs
import smtplib
import httplib
import lxml.etree as etree
import lxml.html.soupparser as soupparser
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# list of keyword
key = ["Redhat","Microsoft+Windows","Apple+Mac+OS","IBM+AIX","HP-UX","Microsoft+SQL+Server","Oracle+MySQL+Server","PostgreSQL","apache","Apache+Tomcat","jboss","Oracle+WebLogic","IBM+WebSphere","Cisco","Squid","PHP","Nginx","Samba","ISC+BIND","Check+Point"]


# create a class for vulnerability, it contains description,severity,cveid,influence and url, it contains also print vulnerability method.

class Vul:

	list=[]
	
	def __init__(self,name,url):

		# initialisation of vulnerability		
			
		self.name = name
		self.date = get_date()
		self.url = url
		self.id = len(Vul.list)
		Vul.list.append(self)


	def get_vul_detail(self):

		# connection and get content
		self.__content = get_webcontent(self.url)

		self.get_description(self.__content)
		self.get_severity(self.__content)
		self.get_CVEID(self.__content)		
		self.get_influence(self.__content)		
	
	def get_description(self,content):

		# get vulnerability description
		soup = BeautifulSoup(content,"lxml")
		string = "漏洞描述".decode('utf-8')
		self.description = ""
		
		# get all of tag who's class is alignRight
		tag_tmp = soup.find('td',class_='alignRight',text=string)

		try:
			for tag in tag_tmp.parent:

				if tag.string == string:
					continue
				else:
					for element in tag:
						try:
							if len(element.string.strip())>0:
								self.description = self.description + element.string.strip()
						except:
							pass

		except AttributeError:			
			pass


	def get_influence(self,content):

		# get vulnerability description
		soup = BeautifulSoup(content,"lxml")
		string = "影响产品".decode('utf-8')
		self.influence = []
		
		# get all of tag who's class is alignRight
		tag_tmp = soup.find('td',class_='alignRight',text=string)

		try:
			for tag in tag_tmp.parent:

				if tag.string == string:
					continue
				else:
					for element in tag:
						try:
							if len(element.string.strip())>0:
								self.influence.append(element.string.strip())
						except:
							pass

		except AttributeError:			
			pass


	def get_severity(self,content):
		
		# get vulnerability severity
		soup = BeautifulSoup(content,"lxml")
		string = "危害级别".decode('utf-8')
		self.severity = ""

		# get all of tag who's class is alignRight
		tag_tmp = soup.find('td',class_='alignRight',text=string)

		try:
			for tag in tag_tmp.parent:

				if tag.string == string:
					continue
				else:
					for element in tag:
						try:

							self.severity = self.severity + "".join(element.string.split()).strip()

						except:
							pass
							
		except AttributeError:					
			pass

	def get_CVEID(self,content):
		
		# get vulnerability severity
		soup = BeautifulSoup(content,"lxml")
		string = "CVE ID"

		# get all of tag who's class is alignRight
		tag_tmp = soup.find('td',class_='alignRight',text=string)

		try:
			self.cve_id = tag_tmp.parent.find('a').string			
				
		except AttributeError:					
			self.cve_id = "Unknown"
	
		
	def print_vul(self):
		
		# Print vulnerability information

		print "[*]"
		print "Name: ", self.name
		print "date: ", self.date
		print "CVE ID: ",self.cve_id
		print "Severity:",self.severity
		
		print "Influence: "
		for instance in self.influence:	
			print instance
		print "Description:",self.description
		print "more information: ",self.url
		print
		print
		
		

def print_summary():

	# Print a summary of vulnerability	

	print
	print "************************* summary *************************"
	print
	
	if len(Vul.list) == 0:
		print "[*]There is no vulnerability today!"
		print
		print "***********************************************************"
		return 1
	else:
		for event in Vul.list:
			print "[*]",event.name
			print "[*]",event.url		
			print
			print
		
		get_detail()
		return 0


def print_welcome():

	# Print a welcome and system time	

	print
	print "**************** Vulnerability alert script ****************"
	print
	print "[*]date: ",get_date()

def get_detail():

	# Get the detail of each vulnerability

	print "************************* detail *************************"
	
	for event in Vul.list:

		event.get_vul_detail()
		while len(event.severity) == 0:

			event.get_vul_detail()

		event.print_vul()



def get_date():

	# get system date	

	return time.strftime("%Y-%m-%d")

def generate_url(keyword):
	
	# generate target url by keywords
	
	url = "http://www.cnvd.org.cn/flaw/list.htm?flag=true&keyword="+keyword+"&condition=1&keywordFlag=0&cnvdId=&cnvdIdFlag=0&baseinfoBeanbeginTime=2016-5-20&baseinfoBeanendTime="+get_date()+"&baseinfoBeanFlag=0&refenceInfo=&referenceScope=-1&manufacturerId=-1&categoryId=-1&editionId=-1&causeIdStr=&threadIdStr=&serverityIdStr=&positionIdStr=";
	return url

def get_webcontent(url):

	# get web content by url	

	# connection
	conn = httplib.HTTPConnection("www.cnvd.org.cn")
	conn.request(method="GET",url=url)
	
	# get content and return
	response = conn.getresponse()
	res = response.read()
	return res

def html_parser(html):

	# parse the html 

	# use beautifulsoup to parse HTML
	soup = BeautifulSoup(html,"lxml")
	try:
		for item in soup.find('tr',class_='current').parent.find_all('a'):
			name = item['title']
			sub_url = "http://www.cnvd.org.cn"+item['href']

			Vul(name,sub_url)

	except AttributeError:
	 
		pass
		
def sendemail(string):

    # create a email instance
    msg = MIMEMultipart()

    # write the content
    msg = MIMEText(string, 'plain', 'utf-8')
    msg['to'] = 'chao.wang@isca.com.cn'
    msg['from'] = 'ingeekvul@sina.com'
    msg['subject'] = 'hello vulnerability'


    try:
        server = smtplib.SMTP()
        server.connect('smtp.sina.com')
        server.login('ingeekvul@sina.com','1qaz@WSX')
        server.sendmail(msg['from'], msg['to'],msg.as_string())
        server.quit()
        print '发送成功'
      
    except Exception, e:  
        print str(e) 

	
def main():

    global key
    
    if os.path.exists('a.txt'):
        os.remove('a.txt')

    f = codecs.open('a.txt','w','utf-8')

    # redirect the output stream to a.txt
    old=sys.stdout
    sys.stdout=f 
     
    print_welcome()	

    # get the information of vulnerability
    for keyword in key:

	    print "[*]test keyword = ",keyword

	    # get web content
	    res = get_webcontent(generate_url(keyword))

	    # parse the html
	    html_parser(res)
	
	# if there are vulnerability, get the detail, if not, redirect the output stream and delete a.txt
    if print_summary() == 1:
	    sys.stdout=old
	    f.close()
	    os.remove(a.txt)
    
    else:
        sys.stdout=old
        f.close()
        f = codecs.open('a.txt','r','utf-8')
        string = f.read()
        sendemail(string)	
        os.remove('a.txt')
        	

main()

	

