import pymongo


class PFile:

    def __init__(self):
        self.name = str()
        self.uid = str()
        self.path = str()
        

        return


class PPyMongoDB:

    def __init__(self, url, port, user, password):
        self.connection = pymongo.MongoClient( 
            "mongodb://" + user + ":" + password 
            + "@" + url + ":" + port + "/?authSource=admin&authMechanism=SCRAM-SHA-1")

        print(self.connection.list_database_names())

        self.admin_db = self.connection["fact_main"]

        self.collection = self.admin_db["file_objects"]

        

        #print(self.collection.find({"processed_analysis.file_type.mime": "application/x-executable"}).count())
             
        for ele in self.collection.find({"parent_firmware_uids" : "bab8d95fc42176abc9126393b6035e4012ebccc82c91e521b91d3bcba4832756_3801088"}):
            
            path = ele["virtual_file_path"]
            path_str = list(path.values())[0]
            path_str = path_str[0]
            path_str = path_str[path_str.index("/"):]
            print(path_str)
            
        
        
            
        

        # print(self.admin_db)    
        return



if __name__ == "__main__":
    client = PPyMongoDB("localhost", "27018",
                        "fact_readonly", "RFaoFSr8b6BMSbzt" )
        
    
    
    pass      
