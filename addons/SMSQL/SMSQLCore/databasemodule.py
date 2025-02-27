import configparser
import logging
import mysql.connector
import pprint
from enum import Enum

class databaseHandler:
    """
    Base class for handling the MySQL database.
    This class has the database object, builds queries and returns data from the MySQL server.
    """

    class dataTypes(Enum):
        """Data types that the database module supports.

        Currently supported:
        VARCHAR, TINYTEXT, TEXT, INT, TINYINT, BIGINT
        """

        VARCHAR = "VARCHAR"
        TINYTEXT = "TINYTEXT"
        TEXT = "TEXT"
        INT = "INT"
        TINYINT = "TINYINT"
        BIGINT = "BIGINT"

    def strQuote(self, data):
        """Stupid function to automatically add quotation for str type objects."""
        if isinstance(data, str):
            return f'"{data}"'
        else:
            return data

    def __init__(self, settings: configparser.ConfigParser, database, testing=False) -> None:
        self.testing = testing
        self.dbHost = settings.get("connections", "mysql-host")
        self.dbuser = settings.get("connections", "mysql-username")
        self.dbpassword = settings.get("connections", "mysql-password")
        if not testing:
            try:
                self.db = mysql.connector.connect(
                    host = self.dbHost,
                    user = self.dbuser,
                    password = self.dbpassword,
                    database = database
                )
            except mysql.connector.Error as e:
                logging.critical(f"Error connecting to MySQL: {e}")
                exit()

            self.cursor = self.db.cursor()
            self.currentQuery = ""
            self.tables = []
            logging.info("Connected to database successfully.")

            # Get the tables we have 
            self.cursor.execute("SHOW TABLES")
            for table in self.cursor:
                name = table[0]
                logging.debug(f'Added table to our list: {name}')
                self.tables.append(name)

            logging.info(f'Database -> {database} has {len(self.tables)} tables.')
        else:
            logging.debug("Running in testing mode. All queryies will be output for debugging.")

    def refreshTables(self):
        """Updates the databaseHandler's internal list of tables using the current MySQL connection."""
        logging.debug("Database -> Refresh table request")
        self.tables = []
        # Get the tables we have 
        self.cursor.execute("SHOW TABLES")
        for table in self.cursor:
            name = table[0]
            logging.debug(f'Added table to our list: {name}')
            self.tables.append(name)
        logging.debug("Database -> Refresh table request complete.")

    def defineColumn(self, name:str|None, dataType:dataTypes, primaryKey:bool=False, unique:bool=False, notNull:bool=False, fin:bool=False, fin_ex:bool=False, auto_inc:bool=False, auto_inc_by:int|None=None, defaultval:int|str=None):
        """
        This method adds a column definition to the MySQL CREATE TABLE statement, add adds it into databaseHandler.currentQuery (str)

        ! - databaseHandler.createTable must be called first to order the operations correctly.

        ! - databaseHandler.wrapex must be called to complete the query.

        Parameters:
            name (None | Str): name of column
            dataType (None | databaseHandler.dataTypes(enum)): Defines datatype of column
            primaryKey (bool): 
            unique (bool): 
            notNull (bool): 
            fin (bool): Specifies the end of the query.
            fin_ex (bool): Specifies the end of the query and executes immediately.
            auto_inc (bool): 
            auto_inc_by (int): Specifies the value to auto increment the entry.
            defaultval (int|str): Specifies the default value of the column upon insertion.
        """
        if name != None and dataType != None:
            self.currentQuery += f'\t{name} {dataType.value}'

            if notNull:
                self.currentQuery += f' NOT NULL'

            if defaultval is not None:
                self.currentQuery += f' DEFAULT {defaultval}'
            
            if auto_inc:
                if auto_inc_by != None:
                    self.currentQuery += f' AUTO_INCREMENT={auto_inc_by}'
                else:
                    self.currentQuery += f' AUTO_INCREMENT'
            
            if primaryKey or unique:
                self.currentQuery += ','
            
            if primaryKey and name != None:
                self.currentQuery += f'\n\tPRIMARY KEY ({name})'
                if not fin or not fin_ex:
                    self.currentQuery += ',\n'

            if unique and name != None:
                if primaryKey:
                    self.currentQuery += f'\tUNIQUE ({name})'
                else:
                    self.currentQuery += f'\n\tUNIQUE ({name})'
                if not fin or not fin_ex:
                    self.currentQuery += ',\n'


        if fin or fin_ex:
            self.currentQuery += f'\n);'
            if fin_ex:
                return self.wrapex()
            logging.debug("Table -> Auto executed on database")
        else: 
            if unique == False and primaryKey == False:
                self.currentQuery += ',\n'
                     
    def createTable(self, name: str):
        """This method starts the CREATE TABLE statement. This should be followed with defineColumn statements."""
        self.currentQuery += f'CREATE TABLE {name} (\n'

    def select(self, table:str, columns:list[str]=[], where:list[str]=None, where_val:list=None, where_and=False, where_or=False, ops:list[str]=[]):
        """
        This method forms a SELECT MySQL statement, add adds it into databaseHandler.currentQuery (str)

        ! - Select executes immedately (Clears currentQuery)

        ! - where, where_val, and ops are aligned to each other. Ex. The value of the column you want to evaluate must be in the same list index as the where location.

        Parameters:
            table (Str): Name of table we are looking in.
            columns (list[str]): list of columns we would like to get the data from. If none is given, all from the table will be returned. '*'
            where (list[str]): column(s) for testing values to meet requirement.
            where_val (list[]): value(s) to test against where columns.
            where_and (bool): specifies we will check multiple where locations.
            where_or (bool): specifies we will use the or statement.
            ops (list[str]): default checks are done with '='. Setting this list with '<' '>' or other operators will change the condition in which we evaluate the where_val.
        """
        self.currentQuery = "SELECT "
        if len(columns) == 0:
            selColm = "*"
        else:
            selColm = ""
            last = columns[-1]
            for column in columns:
                if column != last:
                    selColm += f'{column},'
                else:
                    selColm += column

        self.currentQuery += f'{selColm} FROM {table}'
        if where_and and isinstance(where, list) and isinstance(where_val, list):
            finder_op = " AND "

        if where_or and isinstance(where, list) and isinstance(where_val, list):
            finder_op = " OR "

        if len(ops) > 0:
            self.currentQuery += f' WHERE '
            last = len(where_val)-1
            for i in range(len(where)):
                w_column = where[i]
                w_val = where_val[i]
                op = ops[i]
                self.currentQuery += f'{w_column} {op} {self.strQuote(w_val)}'
                if i != last:
                    self.currentQuery += finder_op
                else:
                    pass
                        
        else:
            self.currentQuery += f' WHERE '
            last = len(where_val)-1
            for i in range(len(where)):
                w_column = where[i]
                w_val = where_val[i]
                self.currentQuery += f'{w_column} = {self.strQuote(w_val)}'
                if i != last:
                    self.currentQuery += finder_op
                else:
                    pass
                    


        #if (where is not None) and (where_val is not None):
        #    self.currentQuery += f' WHERE {where} = "{where_val}"'
        
        self.currentQuery += ";\n"
        return self.wrapex(fetch=True)

    def insert(self, table, columns:list, data:list):
        """
        This method forms a INSERT MySQL statement, add adds it into databaseHandler.currentQuery (str)

        ! - Insert executes immedately (Clears currentQuery)

        Parameters:
            table (Str): Name of table we are looking in.
            columns (list[str]): list of columns we would like to add data to.
            data (list[]): data to be inserted into columns.
        """
        self.currentQuery += f'INSERT INTO {table}'

        last = columns[-1]
        first = columns[0]
        for column in columns:
            if column == first:
                self.currentQuery += '('

            self.currentQuery += column

            if column != last and len(columns) > 1:
                self.currentQuery += ', '

            if column == last:
                self.currentQuery += ')'

        self.currentQuery += " VALUES ("


        for i in range(len(data)):
            last = len(data)-1
            if isinstance(data[i], int):
                self.currentQuery += str(data[i])
            else:
                self.currentQuery += f'"{data[i]}"'

            if i == last:
                self.currentQuery += ')'
            else:
                self.currentQuery += ', '


        self.currentQuery += ";\n"
        return self.wrapex(insert=True)

    def update(self, table, columns:list, data:list, where, wherevalue):
        """
        This method forms a UPDATE MySQL statement, add adds it into databaseHandler.currentQuery (str)

        ! - Update executes immedately (Clears currentQuery)

        Parameters:
            table (Str): Name of table we are looking in.
            columns (list[str]): list of columns we would like to add data to.
            data (list[]): data to be inserted into columns.
        """
        self.currentQuery = f'UPDATE {table} SET '


        selColm = ""
        last = len(columns)-1
        for i in range(len(columns)):
            if i != last:
                selColm += f'{columns[i]} = {data[i]}, '
            else:
                selColm += f'{columns[i]} = {data[i]}'

        
        self.currentQuery += f'{selColm} WHERE {where} = {self.strQuote(wherevalue)};'

        return self.wrapex(insert=True)

    def tableExist(self, table, make=False):
        """Checks for a tables existance. If make is set true it will call the createTable function."""
        if table in self.tables:
            return True #TODO: make an exception instead - Future me here, nahhh. It's fine.
        else:
            logging.warning(f'Table -> {table} - was not present. {make=}')
            if make:
                self.createTable(table)
            return False
        
    def wrapex(self, fetch=False, insert=False):
        """This method executes all queries in databaseHandler.currentQuery - setting fetch returns the results. Setting insert ensures that we commit any modifications."""
        if not self.testing:
            logging.debug(f'Executing current query... -> \n{self.currentQuery}')
            self.cursor.execute(self.currentQuery)

            if self.cursor.rowcount > 0:
                logging.debug(f'{self.cursor.rowcount} rows were affected')

            self.currentQuery = ""
            if self.cursor.warnings is not None:
                logging.warning(f'Query has warnings -> {pprint.pformat(self.cursor.warnings)}')
                return False

            
            if fetch == True:
                results = self.cursor.fetchall()
                if len(results) > 0 and len(results) <= 5:
                    logging.debug(f'Fetch returned {len(results)} results ->\n{pprint.pformat(results)}')
                elif len(results) > 5:
                    logging.debug(f'Fetch returned {len(results)} results -> (Large query output disabled)')
                elif len(results) == 0:
                    logging.debug(f'Fetch returned {len(results)} results')
                return results
                
            if insert == True:
                logging.debug("Database -> committing data...")
                self.db.commit()
                logging.debug(f'Database -> Complete.')
                return True
        else:
            logging.debug(f'wrapex run with {fetch=} {insert=} Query -> \n{pprint.pformat(self.currentQuery)}')

    def insertRawCommand(self, command):
        """Simply inserts your command into the queue with no formatting. Ensure to append a new line at the end."""
        self.currentQuery = command
            



