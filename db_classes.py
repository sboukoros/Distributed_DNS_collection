import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, PickleType
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()
dbhost = "*"
dbuser = "*"
dbpass = "*"
dbname = "*"




class Request(Base):
    __tablename__ = 'requests'
    # Here we define columns for the table we want to recreate
    # Notice that each column is also a normal Python instance attribute.
    #id = Column(Integer, primary_key=True)
    #name = Column(String(250), nullable=False)
    id = Column(Integer, primary_key=True,autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    resolver  = Column(String(100), nullable=False)
    host      = Column(String(100), nullable=False)
    response  = Column(String(10000), nullable=False) 
    ttl       = Column(Integer, nullable=False)
    expired =  Column(Integer,nullable=False)
    

class Resource_Record(Base):
    __tablename__ = 'resourcerecords'
    id = Column(Integer, primary_key=True,autoincrement=True)
    parent_id = Column(Integer, ForeignKey('archivedrequests.id'))
    rtype     = Column(String(20), nullable=False)
    rdata     = Column(String(10000), nullable=False)
    ttl       = Column(Integer, nullable=False) 


class Request_Archive(Base):
    __tablename__ = 'archivedrequests'
    id = Column(Integer, primary_key=True,autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    resolver  = Column(String(100), nullable=False)
    host      = Column(String(100), nullable=False)
    response  = Column(String(10000), nullable=False)
    archivedate = Column(DateTime, nullable=False)
    ttl       = Column(Integer,nullable=False)
    expired =  Column(Integer,nullable=False)
    parsed  =  Column(Integer,nullable=False,default=0)
    children = relationship("Resource_Record", backref="archivedrequests")
# Create an engine that stores data in the local directory's
# sqlalchemy_example.db file.
#engine = create_engine('sqlite:///requests.sqlite3')
engine = create_engine('postgresql://%s:%s@%s/%s'%(dbuser,dbpass,dbhost,dbname))

Base.metadata.create_all(engine)






































