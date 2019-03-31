import pymongo


class PPyMongoDB:

    def __init__(self, url, port, user, password):
        self.connection = pymongo.MongoClient( \ 
            "mongodb://" + user + ":" + password \
            + "@" + url + ":" + port)
        
        return



if __name__ == "__main__":
    pass
