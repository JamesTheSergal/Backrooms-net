from enum import Enum

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