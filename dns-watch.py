#!/usr/bin/env python
# Filename:dns-watch.py 
# -*- coding: utf-8 -*-
"""DNS Watch.

Usage:
  dns-watch [--verbose | -v]
  dns-watch --version
  dns-watch daemon
  dns-watch firewall <host> <ip> 
  dns-watch -h | --help
  dns-watch --archiving
  dns-watch --alexa
  dns-watch --lookupserver
  dns-watch --process
  dns-watch --bench
  
Options:
  -h --help       Show this screen.
  --verbose       Be more talkative.
  --version       Show version/revision.
  daemon          Run request daemon [default: 1].
  firewall        Do a firewall lookup.
  --archiving     Only do archives.
  --alexa         Run the alexa list.
  --lookupserver  Accept lookups and queries.   
  --process       Process the response field into external field.
  --bench         Benchmark modules
"""
from docopt import docopt # cli viz
import subprocess # cli interface
import sqlalchemy # ORM for PostgreSQL
import datetime # for timestamping
import Queue
import math
import csv
import threading
import dns.resolver
import dns.zone
import sys # print
import time
import BaseHTTPServer # firewall port 53 access
from SimpleHTTPServer import SimpleHTTPRequestHandler
import httplib
from subprocess import *
import math
import socket
import ssl
from Queue import Queue
from threading import Thread
from threading import RLock
from backports.ssl_match_hostname import match_hostname, CertificateError
import os
from dns.exception import DNSException
from db_classes import Request # include our classes
from db_classes import Request_Archive
from db_classes import Resource_Record
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy import text
from sqlalchemy.ext.declarative import declarative_base # for basic mapping
import dnslib # Digparser?
from datetime import timedelta # second processing  
from pytimeparse.timeparse import timeparse # timeparsing - might not require the above line anymore KLUDGE
import dns.zone # dns zones and the like
import urllib
import pprint # pretty print for object inspection
import string # explode the serialised rdata object
from dns import resolver,reversename
import re
from CDNs import Lookup
from flask import Flask, request, json, render_template, jsonify                                                                                                                                                                     
import parsedatetime.parsedatetime as pdt

                                                                                                                                                                                                                            
# hardcoded db vars
dbhost = "*"
dbuser = "*"
dbpass = "*"
dbname = "*"

firewall_daemon = Flask("hostname, IP lookup server for firewalls")#,  template_folder='templates') 

# to fix later 
r = dns.resolver.Resolver() 
r.port=6000


CDNs = ["Akamai", "CDN.net", "Chinacache", "Fastly",  "CloudFlare", "CloudFront", "Azure", "CDNetworks", "NetDNA", \
        "Bitgravity", "Cachefly", "CDN77", "Chinanetcenter",  "Edgecast", "Highwinds", "Incapsula", \
        "Internap", "KeyCDN", "Limelight","Squixa"]


def noDIGnity(host,resolver):
    """Replacement function for the previous cli dig approach, does a resolver query for a given host, resolver"""
    try:
        global  r
        # r.nameservers = [resolver]
        # request_data = r.query(host, 'NS', tcp=False)
        ADDITIONAL_RDCLASS = 65535

        #r.nameservers = ["8.8.8.8"]
        #request_data = r.query("any.org", 'ANY', tcp=False)
        query = dns.message.make_query(host, dns.rdatatype.ANY)
        query.flags |= dns.flags.AD
        query.find_rrset(query.additional, dns.name.root, ADDITIONAL_RDCLASS,dns.rdatatype.OPT, create=True, force_unique=True)
        request_data = dns.query.udp(query, resolver, timeout = 2,one_rr_per_rrset=True)
        print host
    
    except DNSException:
        verboseprint("exception handled")
        request_data = 0

    finally:
        return request_data

def update_flag_set(db_session):
        """Runs through database, checks which host queries have expired, sets the flag from 0 to 10, given a database session"""
        get_requests = db_session.query(Request).filter_by(expired=0).all()  
        for r in get_requests:
                verboseprint("Request %s %s %s %s\n-------------------\n" % (r.host, r.resolver, r.timestamp, r.ttl))
                ttl_datetime = r.timestamp + datetime.timedelta(seconds=r.ttl)
                verboseprint("TTL Datetime: %s" % ttl_datetime)
                if (ttl_datetime - datetime.datetime.utcfromtimestamp(time.time())) < datetime.datetime.utcfromtimestamp(0)-datetime.datetime.utcfromtimestamp(0):
                        try:
                                r.expired = 10
                        except:
                                print "Problem saving to DB"
                        finally:
                                return len(get_requests)

def archive_on_flag(db_session):
        """Grabs the requests with updates already done and writes out to other database"""
        get_archivals = db_session.query(Request).filter_by(expired=10).all()  
        # move
        for r in get_archivals:
                try:
                        archive_item = Request_Archive()
                        db_session.add(archive_item) 

                        archive_item.host = r.host
                        archive_item.response = r.response
                        archive_item.resolver = r.resolver
                        archive_item.ttl = r.ttl
                        archive_item.timestamp=str(r.timestamp)
                        archive_item.expired=r.expired
                        archive_item.parsed=0

                        archive_item.archivedate = datetime.datetime.utcfromtimestamp(time.time())
                        # nuke - TODO - remove comment here for deleting item
                        db_session.delete(r) 
                        db_session.commit()
                        verboseprint("Response for %s @%s archived" % (archive_item.host, archive_item.resolver))
                         
                except sqlalchemy.orm.exc.UnmappedError:
                        print "Something went wrong on archive"
               
        # nuke        
        
        return len(get_archivals)

def request_save(hosts, resolver, db_session):
    """Saves a given request to the database"""
    for host in hosts:
        #print "Request save cycle called for %s @%s" % (host, resolver)
        request_dataFromnoDignity = noDIGnity(host, resolver)
        #print request_dataFromnoDignity
        # assigns values

        # Here we creat the sql request
        # expired value has three possible values  
        # 00--> not expired and not updated
        # 10--> expired but not yet updated
        # 11--> expired AND updated so its time to send it to archive db
        #print request_dataFromnoDignity
        if request_dataFromnoDignity != 0:
            new_request = Request()
            db_session.add(new_request)
            new_request.ttl=0
            for rdata in request_dataFromnoDignity.answer:
                if rdata.rdtype==dns.rdatatype.NS:
                    new_request.ttl=rdata.ttl 
            #new_request.ttl = request_dataFromnoDignity.rrset.ttl
            textAnswer = request_dataFromnoDignity.to_text()     #.response
            # serialised_rdata = ""
            # for rdata in textAnswer.rrset:
            #     serialised_rdata += str(rdata) + "," 
            #     verboseprint(serialised_rdata)
            new_request.host = host
            new_request.resolver = resolver
            #new_request.response = serialised_rdata.text() #textAnswer.rrset 
            new_request.response = textAnswer
            new_request.timestamp = datetime.datetime.utcnow()
            new_request.expired = 00
            db_session.commit() # dump out
            verboseprint("%s @%s saved to database" % (host, resolver))
    return 1

def request_update(host, resolver, db_session):
        """Update requests that exist in the database with expired TTLs"""
        print "Request save cycle called for %s @%s" % (host, resolver)
        request_dataFromnoDignity = noDIGnity(host, resolver)
        #print request_dataFromnoDignity
        # assigns values

        # Here we creat the sql request
        # expired value has three possible values  
        # 00--> not expired and not updated
        # 10--> expired but not yet updated
        # 11--> expired AND updated so its time to send it to archive db
        #print request_dataFromnoDignity
        if request_dataFromnoDignity != 0:
            new_request = Request()
            db_session.add(new_request)
            new_request.ttl=0
            for rdata in request_dataFromnoDignity.answer:
                if rdata.rdtype==dns.rdatatype.NS:
                    new_request.ttl=rdata.ttl 
            #new_request.ttl = request_dataFromnoDignity.rrset.ttl
            textAnswer = request_dataFromnoDignity.to_text()     #.response
            # serialised_rdata = ""
            # for rdata in textAnswer.rrset:
            #     serialised_rdata += str(rdata) + "," 
            #     verboseprint(serialised_rdata)
            new_request.host = host
            new_request.resolver = resolver
            #new_request.response = serialised_rdata.text() #textAnswer.rrset 
            new_request.response = textAnswer
            new_request.timestamp = datetime.datetime.utcnow()
            new_request.expired = 00
            db_session.commit() # dump out
            verboseprint("%s @%s saved to database" % (host, resolver))
    

def get_file_as_list(file):
    """Accepts a filename and returns the data as a list"""
    with open(file, "r") as myfile:
        data=myfile.read().splitlines() #.replace('\n', '')
        return data    


def get_db_session():
    """Returns a database session, with a metadata mapping"""
    Base = declarative_base() # not to sure what this does - from SQLAlchemy example

    # temp_db name
    tempdb_name = ('postgresql://%s:%s@%s/%s'%(dbuser,dbpass,dbhost,dbname))
        ## neeeeed to add postgresql name db

    engine = create_engine(tempdb_name)
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    thisSession=scoped_session(DBSession)
    return thisSession

def call_cli(cli_string):
    """Do a command line syscall and return the output data"""
    stream = subprocess.Popen(cli_string, stdout=subprocess.PIPE, shell=True) #, cwd=os.getcwdu() )
    out, err = stream.communicate()
    return out

def check_traceroute_final( ip):
    """Returns a true if final destination translates to host from supplied IP"""
    print "Doing check traceroute check final"
    tr = '''traceroute %s -T | tail -n 1 ''' % (ip)
    request_data = call_cli(tr)
    verboseprint(request_data)
    m=re.search(ip,request_data)
    try:
        return m.group(0)
    except AttributeError:
        return 0

# TODO: set default here to current TTL active - extra param

def get_list_of_recordtype(lookup_host, record_type):
    """Returns a list of RR for the specified host in plain_text string list, line per RR"""
    response_item = r

    # Get all active hosts

    # TODO: change this to include the current TTL active hosts only
    get_requests = db_session.query(Request).from_statement(text("SELECT * FROM requests WHERE host=:lookup_host")).\
                        params(lookup_host=lookup_host).all()
    
    # extract only RR lines with that specific match in that specific location
    
@firewall_daemon.errorhandler(404) # default error handling                                                                                                                                                                                                     
def page_not_found(e):                                                                                                                                                                                                      
    return render_template('404.html'), 404                                                                                                                                                                                 
                                                                                                                                                                                                                            
@firewall_daemon.route("/", methods=['POST', 'GET', 'PUT', 'DELETE']) # generic firewall instruction entry point                                                                                                                                                                                   
def generic_catcher():                                                                                                                                                                                                      
    return render_template('hello.html')                                                                                                                                                                                    
                                                                                                                                                                                                                            
@firewall_daemon.route("/hosts/<string:hostname>/<string:ip>", methods=['GET'])                                                                                                                                                        
def lookup_from_rest(hostname, ip):                                                                                                                                                                                         
    print "Calling the rest functions for lookup with host: %s, ip: %s" % (hostname, ip)                                                                                                                                    
                                                                                                                                                                                                                            
    # KLUDGE: clean up this passing of or redef of globals, elect_officials should be cleaned up                                                                                                                            
    resolvers = get_file_as_list('alexa/cloudResolvers.csv')                                                                                                                                                                
    OpenResolvers = get_file_as_list('alexa/public_resolvers.csv')                                                                                                                                                          

    # if the hostname is not request, do distributed lookup then electofficial
    query = "SELECT count(*) FROM requests WHERE host = '%s';" % (hostname)                                                                                                         
    session1 = get_db_session()
    host_exists = session1.query(Request).from_statement(text("SELECT * FROM requests WHERE host=:lookup_host")).\
        params(lookup_host=hostname).all()
    hosts = []
    hosts.append(hostname)
    if len(host_exists) == 0:
        for resolver in resolvers:
            verboseprint("Resolver: %s" % resolver)
            threading.Thread(target=request_save, args = (hosts,resolver, session1)).start()
    


    result = elect_official(hostname, ip, get_db_session(), resolvers, OpenResolvers)

# if not then do threading stuff

    print result
 
    if result:                                                                                                                                                                                                           
        return 'OK'                                                                                                                                                                                                         
    else:                                                                                                                                                                                                                   
        return 'NotOK'                                                                                                                                                                                                   
    return abort(400)        

@firewall_daemon.errorhandler(404)                                                                                                                                                                                                      
def page_not_found(e):                                                                                                                                                                                                      
    return render_template('404.html'), 404                                                                                                                                                                                 

@firewall_daemon.route("/hosts/<string:hostname>/dates/<string:from_date>/<string:to_date>", methods=['GET'])
def lookup_for_dates(hostname, from_date, to_date):                                                                                                                                                                                         
    print "Doing a date range lookup for %s, from %s, to %s" % (hostname, from_date, to_date)

    # check date validities, or bomb
    cal = pdt.Calendar()
    try:
        from_result = cal.parseDate(from_date) 
        to_result   = cal.parseDate(to_date)
        print from_result
        print to_result

        session1 = get_db_session()

#        history = session.query(Re).join(Address).\


        history = session1.query(Request_Archive).from_statement(text("SELECT * FROM archivedrequests INNER JOIN resourcerecords ON resourcerecords.parent_id = archivedrequests.id WHERE archivedrequests.host=:lookup_host AND archivedrequests.timestamp >= :from_date AND archivedrequests.timestamp <= :to_date;")).\
                      params(lookup_host=hostname, from_date=from_date, to_date=to_date).all()
        
    except ValueError:
        return "Uninterpretable date formats specified"
    print "Doing a date range lookup for %s, from %s, to %s" % (hostname, from_result, to_result)
    return jsonify(json_list = history) 


                                                                                                    
def elect_official(lookup_host, ip, db_session,resolvers,OpenResolvers):
    """Receives a host and IP, follow our logic towards a binary answer, 1 for good, 0 for bad"""
    #testers = db_session.query(Request_Archive,Resource_Record).from_statement(text("SELECT archivedrequests.host, resourcerecords.rdata FROM archivedrequests  inner join resourcerecords on archivedrequests.id = resourcerecords.parent_id where resourcerecords.rtype='1'")).all()
    
    # here i use RAW SQL quert to gather data for testing
    #testers=db_session.execute("SELECT archivedrequests.host, resourcerecords.rdata FROM archivedrequests  inner join resourcerecords on archivedrequests.id = resourcerecords.parent_id where resourcerecords.rtype='1' limit 1000;")
    #breakmevar=0
    # function for NOT actually breaking data
    # def breakme():
    #      global breakmevar
    #      breakmevar=1
    

    #tmp way of getting testing data
    # names = []
    # addrs = []
    ip_list = [] # used for population of IPs
    
    
    ###### tmp cdn list, to be deleted!!!
    majority_timer_list = 0
    existence_timer_list = 0
    cdn_timer_list = 0
    traceroute_timer_list = 0
    
    
    # print lookup_host
    # print ip
    



    # Step 1: If in more than 50% of resolver lists exit(1), else next step
    # Step 2: If in existing lists, next step, else exit(0)
    # Step 3: If in pre-existing CDN list, then exit(1) else next step
    # Step 4: If in distributed reverse lookup in more than 50%, exit(1) else next
    # Step 5: If reachable via server traceroute, exit(1) else exit(0)

    # extraction of A records - dns.rcode.from_text from DB fields
    # tally the top counted and return if similar, then we continue to second step

    response_item = r
    
    count = 0
    total = 0
    
    # fetch all responses for a given hosts
    
    # parse and count all unique IPs, per response
    # Extract all A record IPs for a given domain for all resolvers

    # for row in testers:
    #     names.append(row[0])
    #     addrs.append(row[1])

    # for x in range (0,len(names)):
    # lookup_host=names.pop()
    # ip=addrs.pop()
    # ip_list = [] # used for population of IPs

    # REMEMBER TO UNCOOMENT BELLOW
    get_requests = db_session.query(Request).from_statement(text("SELECT * FROM requests WHERE host=:lookup_host")).\
        params(lookup_host=lookup_host).all()
    

    # THIS IS JUST A TEST QUET FOR FETCHING FAKE DATA
    # 1 Do a count on unique IP for host
    # parse and count all unique IPs, per response
    #print get_requests
    
    t0=time.time() #we start the clock for the majority
    for request in get_requests:
        msgA=dns.message.from_text(request.response.encode('utf8'))
        #print msgA
        for rdata in msgA.answer:
            for items in rdata.items:
                #print items
                if rdata.rdtype==dns.rdatatype.A:
                    total += 1                       
                    #ip_list[request.resolver] = items.to_text())
                    # document resolver hits
                    #print items.to_text()
                    ip_list.append(items.to_text())
                    if ip == items.to_text(): 
                       count += 1


    #
    #
    # We check for majority of the votes!
    #
    #
    majority_timer_list=(time.time()-t0) # we end the clock for thwe majority
    with open('mlList.txt','a') as csvfile:
            csvfile.write(str(majority_timer_list))
            csvfile.write("\n")
    # ip_list.sort()
    print total
    print count
    print ip_list
    if count>=(total/100)*20 and count!=0 and total!=0:
        # print ip_list
        #print '1';
        return(1)        #if we have majority, we exit 1
    
    #
    #
    #
    # We try to see if item exists somewhere in our answers
    # if yes we proceed,otherwise exit with O
    #
    #
    #
    
    
        
    t0=time.time() #we start the clock for the existence
    
    if ip not in ip_list :
        # existence_timer_list.append(time.clock()-t0)    # we stop the timer for the existense
        return(0)# item does not exist anywhere.exit with 0
    existence_timer_list=(time.time()-t0)    # we stop the timer for the existense
    with open('elList.txt','a') as csvfile:
            csvfile.write(str(existence_timer_list))
            csvfile.write("\n")
         






     #
     #
     #
     # We check if item exists in cdn list
     # if yes we return 1, so everything is cool
     # if not, we proceed with further tests
     #maybe here 
     #WE first check public available dns lists.
     #Then we do check is for anycast or dns.
     #
     #
    t0=time.time() #we start the clock for the cdn    
    if Lookup(lookup_host):
         # print "did a lookup"
        cdn_timer_list=(time.time()-t0) # wes top the cdn timer 
        with open('cdnList.txt','a') as csvfile:
            csvfile.write(str(cdn_timer_list))
            csvfile.write("\n")   

        return(1) # exit 1
    
    
    
    #
    #
    # Last check. last hop traceroute from controller
    # its a cli approach
    #
    #
    #
    t0=time.time()

    if  check_traceroute_final(ip):
        traceroute_timer_list=(time.time()-t0)
        with open('trList.txt','a') as csvfile:
            csvfile.write(str(traceroute_timer_list))
            csvfile.write("\n")
        return(1) # exit 0


    


    return(0) #exit 1





        #print "Full list of IPs" % ip_list
        #        ip_list += string.split(str(request.response), ",")
                #print "Length of rdata set for %s is %s" % (request.host, len(str(request.response).split(",")))
        #        count += 1
        #print "Total requests linked to host: %s\nTotal IPs for host: %s" % (count, len(ip_list))        
        #ip_list = filter(None, ip_list)
        #if (ip in ip_list): return 1




        # do reverse lookup to check if IP matches or not

        # try:
        #         addr=reversename.from_address(ip)
        #         print "ReverseName: %s" % str(resolver.query(addr,"PTR")[0])
        #         return 1 # vote yes
        # except:
        #         return 0 # vote no - reverse lookup mapping not working
        

        # # count mapper
        # voter_roll = []
        # voter_roll = dict(zip(ip_list,map(ip_list.count,ip_list)))
        
        # pp = pprint.PrettyPrinter(indent=4)        
        # pp.pprint(voter_roll)

        # # 3 If not the same, do a traceroute with supplied IP, check if supplied IP resolves to supplied host, return 1 if so, 0 if not
        # # handled with a reverse lookup
        # return 0


     





def main(argv):
    verboseprint(arguments)      

    threadList=list()
    updateList=list()

    # some defaults
    hosts = get_file_as_list('alexa/alexa50k.csv')
    resolvers = get_file_as_list('alexa/cloudResolvers.csv')
    OpenResolvers = get_file_as_list('alexa/public_resolvers.csv')
   
    session1 = get_db_session()

    if arguments["firewall"]:
        verboseprint("Host vote requested: %s, %s" % (arguments["<host>"],arguments["<ip>"]))
        if (elect_official(arguments["<host>"],arguments["<ip>"],session1,resolvers,OpenResolvers)):
                print("IP ok")
        else:
                verboseprint("IP tainted")
        exit()

        # archivefirst
    #verboseprint("Updates: %s " % update_flag_set(session1))
    #verboseprint("Archived: %s " % archive_on_flag(session1))
        #exit()

# we start one thread for each resolver
    if arguments["--archiving"]:
        verboseprint("Only archiving process")
        while 1:
            archive_on_flag(session1)
            verboseprint("Archived:  "  )
            time.sleep(600)

    if arguments["--lookupserver"]:
        print "Starting the lookup server"
        firewall_daemon.run(port=51805, debug = True,host='130.83.186.141' ) #ekana allagi edo kai ebala to host                                                                                                                                                                                    
        exit()                                                                                                                                                                                                              

    if arguments["--bench"]:
        names = []
        addrs = []
        dumpcounter=0
        testers=session1.execute("SELECT archivedrequests.host, resourcerecords.rdata FROM archivedrequests  inner join resourcerecords on archivedrequests.id = resourcerecords.parent_id where resourcerecords.rtype='1' limit 1000;")
        for row in testers:
            names.append(row[0])
            addrs.append(row[1])

        for x in range (0,len(names)):
            dumpcounter+=1
            print dumpcounter
            lookup_host=names.pop()
            ip=addrs.pop()
            elect_official(lookup_host, ip, session1,resolvers,OpenResolvers)

        print "Done love"



    if arguments["--alexa"]:
        verboseprint("Only alexa list is being processed")
        for resolver in resolvers:
            resolver=threading.Thread(target=request_save, args = (hosts,resolver, session1))
            resolver.start()
            threadList.append(resolver)
        for thread in threadList:
            thread.join()
        exit(1)
    dumpCounter=0

    if arguments["--process"]:
        verboseprint("The reponses from the archive requests")
        get_archivals = session1.query(Request_Archive).filter(Request_Archive.parsed==0).all()  
        for r in get_archivals:
            dumpCounter+=1
            print dumpCounter
            msgA = dns.message.from_text(r.response.encode('utf8'))
        
            for rdata in msgA.answer:
                for items in rdata.items:
            # write out rdatatype
                    rr_item = Resource_Record()
                    session1.add(rr_item) 
                    rr_item.parent_id = r.id
                    rr_item.rtype = rdata.rdtype
                    rr_item.ttl   = rdata.ttl
                    rr_item.rdata  = items.to_text()
                    r.parsed=1

        session1.commit()
        exit(1)

    for resolver in resolvers:

        #resolver=
        threading.Thread(target=request_save, args = (hosts,resolver, session1)).start()
        #resolver.start()
        #threadList.append(resolver)

# we wait for the resolver-threads to finish        
    #for thread in threadList:
    #   thread.join()

#   time.sleep(20)

    while 1:
       

           #sent query to find those expired
           #it has to check if expired -- from sql query is true
           #then it updates
           #
           #need also tocheck for only one resolver!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
           #do not update like google.com 15 times!!!!
       get_requests = session1.query(Request).filter_by(expired=0).all()  
       for r in get_requests:
               verboseprint("Request %s %s %s %s\n-------------------\n" % (r.host, r.resolver, r.timestamp, r.ttl))
               ttl_datetime = r.timestamp + datetime.timedelta(seconds=r.ttl)
               verboseprint("TTL Datetime: %s" % ttl_datetime)
               if (ttl_datetime - datetime.datetime.utcfromtimestamp(time.time())) < datetime.datetime.utcfromtimestamp(0)-datetime.datetime.utcfromtimestamp(0):
                       try:
                           r.expired = 10
                           verboseprint("Inside updateList")
#
                           session1.commit() # dump out
                           #print r.host
                           request_update(r.host,r.resolver,session1)
#
                       except:
                               print "Problem saving to DB"
                       
#
     
           #wait 10 minites before redo
   
       time.sleep(60)

    verboseprint("Finished")            


if __name__ == "__main__":

        get_revision =  call_cli("git rev-list HEAD --count")
        arguments = docopt(__doc__, version="Revision %s " % get_revision)
        
        if arguments["--verbose"]:
                def verboseprint(*args):
                        # Print each argument separately so caller doesn't need to
                        # stuff everything to be printed into a single string
                        for arg in args:
                                print arg,
                                print
        else:   
                verboseprint = lambda *a: None      # do-nothing function

        main(sys.argv)
