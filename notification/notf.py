#!/usr/bin
import time
import httplib
import lxml.etree as etree
import lxml.html.soupparser as soupparser
from bs4 import BeautifulSoup

# list of vul
list=[]

# list of keyword
key = ["Redhat","Microsoft+Windows","Apple+Mac+OS","IBM+AIX","HP-UX","Microsoft+SQL+Server","Oracle+MySQL+Server","PostgreSQL","apache","Apache+Tomcat","jboss","Oracle+WebLogic","IBM+WebSphere","Cisco","Squid","PHP","Nginx","Samba","ISC+BIND","Check+Point"]

# url to read
url_list = []

def print_summary(list):
	
	print
	print "************************* summary *************************"
	print

	if len(list) > 0 :
		for event in list:
			print "[*]",event
	else:
		print "[*]There is no new vul"
		

	print
	print "************************************************************"

def print_welcome():
	print
	print "**************** Vulnerability alert script ****************"
	print


def get_detail(url_list):
	print
	print "************************* detail *************************"

	for url in url_list:
		conn = httplib.HTTPConnection("www.cnvd.org.cn")
		conn.request(method="GET",url=url)
		response = conn.getresponse()
		res = response.read()
		print "**********"
		print
		print res
		print
		print "**********"

# generate time and date
start_date = time.strftime("%Y-%m-%d")
end_date = time.strftime("%Y-%m-%d")
print_welcome()
print "[*]date: ",start_date

# generate url
for keyword in key:
	url = "http://www.cnvd.org.cn/flaw/list.htm?flag=true&keyword="+keyword+"&condition=1&keywordFlag=0&cnvdId=&cnvdIdFlag=0&baseinfoBeanbeginTime="+start_date+"&baseinfoBeanendTime="+end_date+"&baseinfoBeanFlag=0&refenceInfo=&referenceScope=-1&manufacturerId=-1&categoryId=-1&editionId=-1&causeIdStr=&threadIdStr=&serverityIdStr=&positionIdStr=";
	print "[*]target keyword = ",keyword


	# get web content
	conn = httplib.HTTPConnection("www.cnvd.org.cn")
	conn.request(method="GET",url=url)
	response = conn.getresponse()
	res = response.read()

	# use beautifulsoup to parse HTML
	soup = BeautifulSoup(res,"lxml")
	try:
		for item in soup.find('tr',class_='current').parent.find_all('a'):
			list.append(item['title'])
			sub_url = "http://www.cnvd.org.cn"+item['href']
			url_list.append(sub_url)

		print "	[*] New %s vul found" % keyword				

	except AttributeError:
	
		print "	[*] No %s vul found" % keyword

print_summary(list)
get_detail(url_list)

	

