#!/usr/bin/env python3
from datetime import datetime
import redis
import os
from subprocess import check_output
import json
from config import REDIS_HOST, PATH_TO_MOUNT, CATEGORY_REGEXES, SQLALCHEMY_DATABASE_URI
import logging
import pickle
import hashlib
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import *
from sqlalchemy.types import Time
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship, sessionmaker, configure_mappers
from sqlalchemy_searchable import make_searchable
import sys
import re
import mimetypes
import traceback
from sqlalchemy_utils.types import TSVectorType
from guessit import guessit

r = redis.Redis(host=REDIS_HOST)
base = declarative_base()
engine = create_engine(SQLALCHEMY_DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()
make_searchable()


tag_media_association_table = Table('tag_media',
                                    base.metadata,
                                    Column('tag_id',
                                           Integer,
                                           ForeignKey('tag.tag_id')),
                                    Column('file_hash',
                                           VARCHAR,
                                           ForeignKey('media.file_hash',
                                                      ondelete="cascade")))


class Category(base):
    __tablename__ = "category"

    category_id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True, nullable=False)
    media = relationship("Media", back_populates="category")


class Tag(base):
    __tablename__ = "tag"
    search_vector = Column(TSVectorType('name'))

    tag_id = Column(Integer, primary_key=True)
    name = Column(Text, unique=True, nullable=False)

    media = relationship("Media",
                         secondary=tag_media_association_table,
                         back_populates="tags")


class File(base):
    __tablename__ = "files"
    search_vector = Column(TSVectorType('path'))

    file_hash = Column(VARCHAR,
                       ForeignKey("media.file_hash"),
                       nullable=False)
    path = Column(Text, nullable=False, unique=True, primary_key=True)


class Media(base):
    __tablename__ = "media"

    name = Column(Text, nullable=False)
    file_hash = Column(VARCHAR, nullable=False, unique=True, primary_key=True)
    mediainfo = Column(postgresql.JSONB, nullable=False)
    lastModified = Column(DateTime, nullable=False)
    mimetype = Column(Text, nullable=False)
    search_vector = Column(TSVectorType('name'))

    # media requires a category
    category_id = Column(Integer,
                         ForeignKey("category.category_id"),
                         nullable=False)
    category = relationship("Category")

    tags = relationship("Tag",
                        secondary=tag_media_association_table,
                        back_populates="media",
                        cascade="all")


# Create non existing Tables
configure_mappers()
base.metadata.create_all(engine)


class Operation:

    def __init__(self, path, operation):
        self.path = path
        self.operation = operation
        self.operations = {
            "INIT": self.op_init,
            "CREATE": self.op_create,
            "RENAME": self.op_rename,
        }

    def operate(self):
        logging.debug("operation: {} {}".format(self.path, self.operation))
        self.operations[self.operation]()

    # INOTIFY operation handlers
    def op_init(self):
        logging.debug("Initial Hash: {}".format(self.path))
        self.op_create()

    def op_create(self):
        filepath = os.path.join(PATH_TO_MOUNT, self.path)
        with open(filepath, 'rb') as f:
            # Hash the file
            hash_str = hashlib.sha256(f.read()).hexdigest()

            # Get mime type
            (full_mime, encoding) = mimetypes.guess_type(filepath)
            logging.debug("Path: {} MIME: {}".format(filepath, full_mime))

            # Create Medium and add to database
            m = Media(file_hash=hash_str,
                      name=os.path.basename(self.path),
                      lastModified=datetime.now(),
                      mimetype=full_mime,
                      mediainfo=populate_mediainfo(filepath, full_mime),
                      category=get_create_category(full_mime.split("/")[0]))
            try:
                session.add(m)
                session.commit()
            except:
                logging.error(sys.exc_info())
                session.rollback()

            f = File(file_hash=hash_str, path=filepath)
            try:
                session.add(f)
                session.commit()
            except:
                logging.error(sys.exc_info())
                session.rollback()

    def op_rename(self):
        pass

    def op_truncate(self):
        pass

    def op_mkdir(self):
        pass

    def op_deldir(self):
        pass


def ffprobe(filename):
    try:
        result = check_output(["ffprobe", "-v", "quiet",
                               "-show_format", "-show_streams",
                               "-print_format", "json",
                               filename])
        # yes, decoding sometimes fails too :(
        return json.loads(result.decode('utf-8').strip())

    except:
        logging.warning("ffprobe error: {}".format(sys.exc_info()))
        return dict()


def populate_mediainfo(filepath, full_mime):
    mime = full_mime.split("/")[0]
    merged = {}
    if mime == "video":
        mediainfo = ffprobe(filepath)
        mediainfo['format'].pop('filename', None)
        guess = guessit(filepath)

        merged = {"ffprobe": mediainfo,"guessit": guess}
    return json.dumps(merged)


def categorize(path):
    for c, rules in CATEGORY_REGEXES.items():
        for rule in rules:
            if re.match(rule, path, re.IGNORECASE):
                category = c
                break
    return category


def get_create_category(name):
    r = session.query(Category).filter_by(name=name).first()
    if not r:
        r = Category(name=name)
        session.add(r)
        session.commit()
    return r


def process_element():
    res = r.rpop("pending")
    try:
        if res is not None:
            split = res.decode().rsplit(' ', 1)
            op = Operation(*split)
            op.operate()
    except Exception as e:
        logging.error("{}\n {}".format(e, sys.exc_info()))
        traceback.print_stack()
        r.lpush("failed", res)


def process_queue():
    logging.info("Starting processing loop")
    while True:
        process_element()


logging.basicConfig(level=logging.DEBUG)
process_queue()
