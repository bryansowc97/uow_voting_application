import csv
import os

class User:
  def __init__(self, username, first_name, last_name, email):
    self.username = username
    self.first_name = first_name
    self.last_name = last_name
    self.email = email

def process_csv(filename):
    affix = ".csv"
    if filename != None and affix in filename:
        # Declaration of list variables
        list_of_passed = []
        list_of_failed = []

        # Open validated '.csv' file
        file = open(filename)
        reader = csv.reader(file)

        ''' 
            Written under assumption that CSV is drafted with header specification 
                                            -> (username, first_name, last_name, email)
            
            Entries that pass validataion are stored in 'list_of_passed'.

            Entries that fail validation are appended with its source file line number 
            and stored in 'list_of_failed'.
        '''
        next(reader) # Discard headers
        count = 1
        for row in reader:
            indicator = True
            for field in row:
                if field == "":
                    indicator = False
            if indicator == True:
                obj = User(row[0], row[1], row[2], row[3])
                list_of_passed.append(obj)
            else:
                row.append("Line " + str(count))
                list_of_failed.append(row)
            count += 1
        
        # Test lines - Discard while integrating
        for obj in list_of_passed:
            print(obj.username + " | " + obj.first_name + " | " + obj.last_name + " | " + obj.email)
        print("")
        for obj in list_of_failed:
            print(obj)

        
        ''' Use sequence unpacking to get both lists -> 'pList, fList = process_csv(YOUR_FILE_NAME)'
            Reduce return statement to one list if desired. '''
        return list_of_passed, list_of_failed
    else:
        print("Error. File parsed needs to be of '.csv' format.")

process_csv('C:\\Users\\Bryan\\Downloads\\MOCK_DATA (1).csv')