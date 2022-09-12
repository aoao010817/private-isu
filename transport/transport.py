#!/bin/python3

import pymysql
from PIL import Image
import boto3
import uuid

connection = pymysql.connect(host='sst-internship-db.ch3v0aklu64f.ap-northeast-1.rds.amazonaws.com',
                             user='admin',
                             password='password',
                             database='isuconp',
                             cursorclass=pymysql.cursors.DictCursor)

s3 = boto3.resource('s3')
bucket = s3.Bucket("sst-internship-s3")


with connection:
    with connection.cursor() as cursor:
        sql = "SELECT id, mime, imgdata FROM posts LIMIT 1"
        cursor.execute(sql)
        results = cursor.fetchall()

        for result in results:
            id = result["id"]
            uuid = uuid.uuid4()
            if result["mime"][6:] == "jpeg":
                file_path = "./img.jpg" 
                upload_name = str(uuid) + "." + "jpg"
            else:
                file_path = "./img." + result["mime"][6:]
                upload_name = str(uuid) + "." + result["mime"][6:]
            
            with open(file_path, 'wb') as img:
                img.write(result["imgdata"])

            img = Image.open(file_path)
            img.save(file_path)

            bucket.upload_file(file_path, "images/" + upload_name)

            sql = "UPDATE posts SET s3_filename=%s WHERE id=%s"
            param = (upload_name, id)
            cursor.execute(sql, param)
            connection.commit()

            if id % 100 == 0:
                print(id)