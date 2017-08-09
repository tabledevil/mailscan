#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re

# basepath="/tank/data/cases/2017031310000018_mileng_coe/exchange/Mailbox Database 0825066855/Mailbox Database 0825066855.edb"
# basepath="/tank/data/cases/2017031310000018_mileng_coe/exchange/Mailbox Database 0825066855/Mailbox Database 0825066855.edb/Director DEU OF-5 Janeke"
basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    relpath = os.sep.join(root.split(os.sep)[basecount:])
    for file in files:
        filename=root+os.sep+file
        relfilename=relpath+os.sep+file
        try:

            # file_handle=open(root+os.sep+file)
            msg=email.message_from_file(open(filename,encoding="latin-1"))
            if msg.is_multipart():
                if "From" in msg.keys():
                    msg_from=msg.get("From").replace(";",",")
                else:
                    msg_from="UNKNOWN"
                if "Date" in msg.keys():
                    msg_date=msg.get("Date").replace(";",",")
                else:
                    msg_date="UNKNOWN"

                for part in msg.walk():
                    if part.get_filename() is not None:
                        att_hash=hashlib.md5(part.get_payload(decode=True)).hexdigest()
                        att_filename=part.get_filename().replace(";",",")
                        att_mimetype=part.get_content_type().replace(";",",")
                        msg_filename=relfilename.replace(";",",")
                        print("%s;%s;%s;%s;%s;%s" % (att_filename,att_mimetype,att_hash,msg_date,msg_from,msg_filename))
                        # print("%s;%s" % (part.get_filename(),md5.hexdigest()))
            else:
                pass
                # print("--------------------------------------------")
                # print(filename)
                # print("--------------------------------------------")



            # print("+"+filename)
            # for part in msg.iter_attachments():
            #     # if part.is_attachment():
            #     att_mimetype=part.get_content_type()
            #     att_filename=part.get_filename()
            #     # if "multipart/alternative" in att_mimetype:
            #     #     submsg=email.message_from_string(part.get_payload(decode=True))
            #     #     print("submessage has %d attachments"%len(submsg.get_payload()))
            #     # # if "application/octet-stream" in att_mimetype:
            #     # #     print(att_filename)
            #     # if "macroenabled" in att_mimetype:
            #     #     open(att_filename,'wb').write(attachment.get_payload(decode=True))
            #     if att_filename is not None:



        except Exception as e:
            print("-"+filename)
            print (e)

"""
      4 application/force-download
     38 application/msword
    423 application/octet-stream
    321 application/pdf
     27 application/rtf
      1 application/vnd.ms-excel
      6 application/vnd.ms-excel.sheet.macroenabled.12
      4 application/vnd.ms-powerpoint
     11 application/vnd.openxmlformats-officedocument.presentationml.presentation
      8 application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
     56 application/vnd.openxmlformats-officedocument.wordprocessingml.document
      1 application/zip
      2 audio/mpeg
     64 image/gif
    894 image/jpeg
      5 image/jpg
    539 image/png
     32 message/rfc822
   3019 multipart/alternative
     11 multipart/signed
      1 'str' object has no attribute 'get_content_type'
      1 -/tank/data/cases/2017031310000018_mileng_coe/exchange/Mailbox Database 0825066855/Mailbox Database 0825066855.edb/Director DEU OF-5 Janeke/Inbox/Janeke/138
     88 text/calendar
      4 text/directory
     25 text/html
    210 text/plain
      1 video/mp4
      1 video/x-ms-wmv
"""
#20170221_NU_MILENG COE_NDPP-Darft-Targets-Related-Activities.xlsm
