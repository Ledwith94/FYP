#!/usr/bin/python

# /media/paul/USB DISK/Ubuntu16-Original.vhd
# /media/paul/USB DISK/Windows7-Original.vhd
import argparse
import csv
import datetime
import hashlib
import os
import time
import pytsk3
import pyvhdi


from pymongo import MongoClient


class vhdi_Img_Info(pytsk3.Img_Info):
    def __init__(self, vhdi_file):
        self._vhdi_file = vhdi_file
        super(vhdi_Img_Info, self).__init__(
            url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._vhdi_file.close()

    def read(self, offset, size):
        self._vhdi_file.seek(offset)
        return self._vhdi_file.read(size)

    def get_size(self):
        return self._vhdi_file.get_media_size()


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


def mongo_insert(insert):
    client = MongoClient()
    db = client['dedupe']
    files = db.files
    file_id = files.insert_one(insert).inserted_id


def acq_insert(insert):
    client = MongoClient()
    db = client['Acquisition']
    files = db.files
    file_id = files.insert_one(insert).inserted_id

def acquisition_exists(name):
    client = MongoClient()
    db = client['Acquisition']
    files = db.files
    if bool(files.find_one({"Name": name})):
        return True
    else:
        return False


def already_exists(hash):
    client = MongoClient()
    db = client['dedupe']
    files = db.files
    if bool(files.find_one({"SHA1 Hash": hash})):
        files.update_one({"SHA1 Hash": hash}, {'$addToSet': {"Acquisition": outname}})
        return True
    else:
        return False

def blacklisted(hash):
    client = MongoClient()
    db = client['blacklist']
    files = db.files
    if bool(files.find_one({"SHA1 Hash": hash})):
        return True
    else:
        return False


def directoryRecurse(directoryObject, parentPath, insert_list):
    for entryObject in directoryObject:
        if entryObject.info.name.name in [".", ".."]:
            continue

        try:
            f_type = entryObject.info.meta.type

        except:
            #print "Cannot retrieve type of", entryObject.info.name.name
            continue

        try:

            filepath = '/%s/%s' % ('/'.join(parentPath), entryObject.info.name.name)
            outputPath = './%s/%s/' % (str(partition.addr), '/'.join(parentPath))

            if f_type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entryObject.as_directory()
                parentPath.append(entryObject.info.name.name)
                insert_list = directoryRecurse(sub_directory, parentPath, insert_list)
                parentPath.pop(-1)
                # print "Directory: %s" % filepath

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG and entryObject.info.meta.size != 0:
                filedata = entryObject.read_random(0, entryObject.info.meta.size)
                # print "match ", entryObject.info.name.name
                md5hash = hashlib.md5()
                md5hash.update(filedata)
                sha1hash = hashlib.sha1()
                sha1hash.update(filedata)
                # start_block = None
                # finish_block = None
                # block_length = None
                # for attr in entryObject:
                #     for run in attr:
                #         start_block = run.addr
                #         finish_block = run.addr + run.len
                #         block_length = run.len

                # wr.writerow([int(entryObject.info.meta.addr), '/'.join(parentPath) + entryObject.info.name.name,
                #              datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime(
                #                  '%Y-%m-%d %H:%M:%S'), int(entryObject.info.meta.size),
                #              md5hash.hexdigest(),
                #              sha1hash.hexdigest(), filepath])

                insert = {"SHA1 Hash": sha1hash.hexdigest(),
                          "MD5 Hash": md5hash.hexdigest(),
                          "inode": int(entryObject.info.meta.addr),
                          "Name": '/'.join(parentPath) + entryObject.info.name.name,
                          "Creation Time": datetime.datetime.fromtimestamp(entryObject.info.meta.crtime).strftime(
                              '%Y-%m-%d %H:%M:%S'),
                          "Size": int(entryObject.info.meta.size),
                          "File Path": "Extracted_files/" + filepath,
                          "Acquisition": [outname],
                          # "Start Block": start_block,
                          # "Finish Block": finish_block,
                          # "Block Length": block_length
                          }
                if args.blacklist and blacklisted(sha1hash.hexdigest()):
                    print "Blacklisted File Found"
                    print insert
                    raw_input("Press enter to continue")
                elif already_exists(sha1hash.hexdigest()) is False:
                    mongo_insert(insert)
                    if not os.path.exists("Extracted_files/" + outputPath):
                        os.makedirs("Extracted_files/" + outputPath)
                    extractFile = open("Extracted_files/" + outputPath + entryObject.info.name.name, 'w')
                    extractFile.write(filedata)
                    extractFile.close()

        except IOError as e:
            print e
            continue


startTime = datetime.datetime.now()
argparser = argparse.ArgumentParser(
    description='Hash files recursively from a forensic image and optionally extract them')
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
    '-t', '--type',
    dest='imagetype',
    action="store",
    type=str,
    default=False,
    required=True,
    help='Specify image type e01 or raw'
)
argparser.add_argument(
    '-a', '--acquisition',
    dest='acquisition',
    action="store",
    type=str,
    default=False,
    required=True,
    help='Specify acquisition name'
)
argparser.add_argument(
    '--enable-automation',
    dest='blacklist',
    action="store",
    type=bool,
    default=False,
    required=False,
    help='Enable auto file discovery'
)
args = argparser.parse_args()
dirPath = '/'
insert_list = []

if not os.path.exists("Extracted_files/"):
    os.makedirs("Extracted_files/")

i = 0
while acquisition_exists(args.acquisition):
    i += 1
outname = args.acquisition + ".csv"
outfile = open(outname, 'w')

outfile.write('"Inode","Full Path","Creation Time","Size","MD5 Hash","SHA1 Hash", "File Path\n')
wr = csv.writer(outfile, quoting=csv.QUOTE_ALL)
if args.imagetype == "raw":
    print "Raw Type"
    imagehandle = pytsk3.Img_Info(url=args.imagefile)
else:
    print "Virtual Hard Disk"
    vhdi_file = pyvhdi.file()
    vhdi_file.open(args.imagefile)
    imagehandle = vhdi_Img_Info(vhdi_file)

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
    directoryRecurse(directoryObject, [], insert_list)

row_count = sum(1 for row in open(outname, "r"))

insert = {"Name": outname,
          "Creation Time": time.ctime(os.path.getctime(outname)),
          "File Count": row_count,
          "Image Size": str(pytsk3.Img_Info.get_size(imagehandle)),
          "MD5 Hash": "NULL",
          "SHA1 Hash": "NULL",
          "All Files": insert_list
          }
acq_insert(insert)
print datetime.datetime.now() - startTime