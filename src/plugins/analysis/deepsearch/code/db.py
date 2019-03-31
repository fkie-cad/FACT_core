import pymongo


class PFile:

    def __init__(self):
        self.name = str()
        self.uid = str()
        self.files = list()

        return

class PFolder:

    def __init__(self):
        self.name = str()
        self.folders = list()
        self.files = list()

        return


class PFirmware:

    def __init__(self):
        self.root = PFolder()
        self.root.name = "/"
        
        return 


class PPyMongoDB:

    def __init__(self, url, port, user, password):
        self.connection = pymongo.MongoClient( 
            "mongodb://" + user + ":" + password 
            + "@" + url + ":" + port + "/?authSource=admin&authMechanism=SCRAM-SHA-1")

        print(self.connection.list_database_names())

        self.admin_db = self.connection["fact_main"]

        self.collection = self.admin_db["file_objects"]

        print(self.collection.find({"processed_analysis.file_type.mime": "application/x-executable"}).count())
             
        
        
            
        

        # print(self.admin_db)    
        return



if __name__ == "__main__":
    client = PPyMongoDB("localhost", "27018",
                        "fact_readonly", "RFaoFSr8b6BMSbzt" )
        
    
    
    pass      
