#!/usr/bin/python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2018  Fraunhofer FKIE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import logging
import sys

from storage.MongoMgr import MongoMgr
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from helperFunctions.dataConversion import convert_str_to_time
from helperFunctions.fact_init import setup_argparser, setup_logging, load_config


PROGRAM_NAME = "FACT Database Migration Assistant"
PROGRAM_VERSION = "0.2"
PROGRAM_DESCRIPTION = "Converts old database entries into the new format"


def add_parent_firmware_list_to_file_object(db_service):
    query = db_service.file_objects.find({}, {"_id": 1, "virtual_file_path": 1, "parent_firmware_uids": 1})
    for result in query:
        if "parent_firmware_uids" not in result:
            parent_firmware_list = [p for p in result["virtual_file_path"]]
            db_service.update_object_field(uid=result["_id"], field="parent_firmware_uids", value=parent_firmware_list)
            logging.debug("inserted 'parent_firmware_uids' in {} with value {}".format(result["_id"], parent_firmware_list))


def convert_release_dates_to_date_object_format(db_service):
    query = db_service.firmwares.find({}, {"_id": 1, "release_date": 1})
    for entry in query:
        firmware_id = entry["_id"]
        date = entry["release_date"]
        if type(date) == str:
            logging.debug("converting date of {}".format(firmware_id))
            try:
                updated_entry = convert_str_to_time(date)
                db_service.update_object_field(uid=firmware_id, field="release_date", value=updated_entry)
            except Exception as e:
                logging.error("could not convert release date entry: {} {}".format(sys.exc_info()[0].__name__, e))


def convert_comments_to_new_format(db_service):
    for collection in [db_service.firmwares, db_service.file_objects]:
        comment_query = collection.find({"comments": {"$type": "object"}}, {"_id": 1, "comments": 1})
        for entry in comment_query:
            firmware_id = entry["_id"]
            comment_field = entry["comments"]
            if type(comment_field) == dict:
                logging.debug("converting comments of {}".format(firmware_id))
                try:
                    updated_comment_field = [
                        {"time": time, "author": comment_field[time][0], "comment": comment_field[time][1]}
                        for time in comment_field
                    ]
                    db_service.update_object_field(firmware_id, "comments", updated_comment_field)
                except Exception as e:
                    logging.error("could not convert comment entry: {} {}".format(sys.exc_info()[0].__name__, e))


if __name__ == '__main__':
    args = setup_argparser()
    config = load_config(args)
    setup_logging()

    logging.info("Trying to start Mongo Server and initializing users...")
    mongo_manger = MongoMgr(config=config, auth=False)
    db_service_frontend_editing = FrontendEditingDbInterface(config)

    convert_comments_to_new_format(db_service_frontend_editing)
    convert_release_dates_to_date_object_format(db_service_frontend_editing)
    add_parent_firmware_list_to_file_object(db_service_frontend_editing)

    sys.exit()
