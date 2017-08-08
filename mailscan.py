#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import email
import hashlib

basepath="/tank/data/cases/2017031310000018_mileng_coe/exchange/Mailbox Database 0825066855/Mailbox Database 0825066855.edb"
# basepath="/tank/data/cases/2017031310000018_mileng_coe/exchange/Mailbox Database 0825066855/Mailbox Database 0825066855.edb/Director DEU OF-5 Janeke"

# traverse root directory, and list directories as dirs and files as files
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    # print((len(path) - 1) * '---', os.path.basename(root))
    for file in files:
        # print(len(path) * '---', file)
        filename=root+os.sep+file
        try:
            # p = sub.Popen('file '+filename,stdout=sub.PIPE,stderr=sub.PIPE)
            # output, errors = p.communicate()
            # print(output)

            # file_handle=open(root+os.sep+file)
            msg=email.message_from_file(open(filename,encoding="latin-1"))
            if msg.is_multipart():
                pass
                for part in msg.walk():
                    if part.get_filename() is not None:
                        md5=hashlib.md5(part.get_payload(decode=True))
                        print("%s;%s;%s;%s" % (part.get_filename(),part.get_content_type(),md5.hexdigest(),filename))
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
