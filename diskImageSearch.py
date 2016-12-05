#!/usr/bin/python

import pytsk3
import datetime
import argparse
import hashlib
import csv
import os
import re
from pymongo import MongoClient
from shutil import copyfile



class ewf_Img_Info(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        self.memory = 0
        super(ewf_Img_Info, self).__init__(
            url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def mongo_insert(insert, hash):
    client = MongoClient()
    db = client['dedupe']
    files = db.files
    if files.find_one({"MD5 Hash": hash}) is None:
        file_id = files.insert_one(insert).inserted_id
        return True
    else: return False

def directoryRecurse(directoryObject, parentPath, count):
    for entryObject in directoryObject:
        if entryObject.info.name.name in [".", ".."]:
            continue

        try:
            f_type = entryObject.info.meta.type

        except:
            print "Cannot retrieve type of", entryObject.info.name.name
            continue

        try:

            filepath = '/%s/%s' % ('/'.join(parentPath), entryObject.info.name.name)
            outputPath = './%s/%s/' % (str(partition.addr), '/'.join(parentPath))

            if f_type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entryObject.as_directory()
                parentPath.append(entryObject.info.name.name)
                count += directoryRecurse(sub_directory, parentPath, count)
                parentPath.pop(-1)
                # print "Directory: %s" % filepath

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG and entryObject.info.meta.size != 0:
                searchResult = re.match(args.search, entryObject.info.name.name)
                if not searchResult:
                    continue
                filedata = entryObject.read_random(0, entryObject.info.meta.size)
                # print "match ", entryObject.info.name.name
                count += 1
                md5hash = hashlib.md5()
                md5hash.update(filedata)
                sha1hash = hashlib.sha1()
                sha1hash.update(filedata)
                wr.writerow([int(entryObject.info.meta.addr), '/'.join(parentPath) + entryObject.info.name.name,
                             datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime(
                                 '%Y-%m-%d %H:%M:%S'), int(entryObject.info.meta.size), md5hash.hexdigest(),
                             sha1hash.hexdigest()])
                insert = {"inode": int(entryObject.info.meta.addr),
                          "Name": '/'.join(parentPath) + entryObject.info.name.name,
                          "Creation Time": datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime(
                              '%Y-%m-%d %H:%M:%S'),
                          "Size": int(entryObject.info.meta.size),
                          "MD5 Hash": md5hash.hexdigest(),
                          "SHA1 Hash": sha1hash.hexdigest()}
                if mongo_insert(insert, md5hash.hexdigest()) is True:
                    extractFile = open("Extracted_files/" + entryObject.info.name.name, 'w')
                    extractFile.write(filedata)
                    extractFile.close()
        except IOError as e:
            print e
            continue
    return count


argparser = argparse.ArgumentParser(description=
                                    'Hash files recursively from a forensic image and optionally extract them')
argparser.add_argument(
    '-i', '--image',
    dest='imagefile',
    action="store",
    type=str,
    default=None,
    required=True,
    help='E01 to extract from'
)
argparser.add_argument(
    '-p', '--path',
    dest='path',
    action="store",
    type=str,
    default='/',
    required=False,
    help='Path to recurse from, defaults to /'
)
argparser.add_argument(
    '-o', '--output',
    dest='output',
    action="store",
    type=str,
    default='inventory.csv',
    required=False,
    help='File to write the hashes to'
)
argparser.add_argument(
    '-s', '--search',
    dest='search',
    action="store",
    type=str,
    default='.*',
    required=False,
    help='Specify search parameter e.g. *.lnk'
)
argparser.add_argument(
    '-e', '--extract',
    dest='extract',
    action="store_true",
    default=False,
    required=False,
    help='Pass this option to extract files found'
)
argparser.add_argument(
    '-t', '--type',
    dest='imagetype',
    action="store",
    type=str,
    default=False,
    required=True,
    help='Specify image type e01 or raw'
)
args = argparser.parse_args()
dirPath = args.path
if not args.search == '.*':
    print "Search Term Provided", args.search
outfile = open(args.output, 'w')
outfile.write('"Inode","Full Path","Creation Time","Size","MD5 Hash","SHA1 Hash"\n')
wr = csv.writer(outfile, quoting=csv.QUOTE_ALL)
file_count = 0
if args.imagetype == "raw":
    print "Raw Type"
    imagehandle = pytsk3.Img_Info(url=args.imagefile)
partitionTable = pytsk3.Volume_Info(imagehandle)
for partition in partitionTable:
    print partition.addr, partition.desc, "%ss(%s)" % (partition.start, partition.start * 512), partition.len
    try:
        filesystemObject = pytsk3.FS_Info(imagehandle, offset=(partition.start * 512))
    except:
        print "Partition has no supported file system"
        continue
    print "File System Type Dectected ", filesystemObject.info.ftype
    directoryObject = filesystemObject.open_dir(path=dirPath)
    print "Directory:", dirPath
    file_count += directoryRecurse(directoryObject, [], file_count)

# hashmatch(args.output)
print "Size of disc image = " + str(pytsk3.Img_Info.get_size(imagehandle)) + " bytes"
print "Numeber of Files = ", file_count

# f = open(args.output, 'rt')
# com = []
# a = 0
# b = 1
# memory = 0
# key = 0
# check = False
# try:
#     reader = csv.reader(f)
#     for row in reader:
#         com.append(row[4])
#         if check is True:
#             memory += int(row[3])
#         check = True
#     com.sort()
#
#     while b < com.__len__():
#         if com[a] == com[b]:
#             print com[a]
#             key = com[a]
#         a = a + 1
#         b = b + 1
#
#     for row in reader:
#         print b
#         if row[4] == key:
#             print row
# finally:
#     f.close()
# print "Size of data = " + str(memory) + " bytes"
