# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""PostGIS database connector for UCID data.

This module provides a connector for reading and writing UCID data
to PostgreSQL/PostGIS databases. Requires `sqlalchemy` and `psycopg2`.
"""

from typing import Any

try:
    import sqlalchemy  # type: ignore[import-untyped]
except ImportError:
    sqlalchemy = None  # type: ignore[assignment]


class PostGISConnector:
    """Connector for PostgreSQL/PostGIS databases.

    Provides methods for reading and writing UCID data to a
    PostgreSQL database with PostGIS extension.

    Attributes:
        engine: SQLAlchemy database engine.

    Example:
        >>> connector = PostGISConnector("postgresql://user:pass@localhost/db")
        >>> connector.write_ucids(ucid_data, "ucid_scores")
    """

    def __init__(self, connection_string: str) -> None:
        """Initialize the PostGIS connector.

        Args:
            connection_string: SQLAlchemy connection string.
                Example: "postgresql://user:pass@localhost:5432/dbname"

        Raises:
            ImportError: If sqlalchemy or psycopg2 is not installed.
        """
        if sqlalchemy is None:
            raise ImportError("sqlalchemy not installed - run: pip install sqlalchemy psycopg2-binary")
        self.engine = sqlalchemy.create_engine(connection_string)

    def write_ucids(
        self,
        ucids: list[dict[str, Any]],
        table_name: str,
        if_exists: str = "append",
    ) -> None:
        """Write UCID data to a database table.

        Args:
            ucids: List of UCID dictionaries to write.
            table_name: Name of the target table.
            if_exists: How to handle existing table. Options:
                - "append": Add rows to existing table
                - "replace": Drop and recreate table
                - "fail": Raise error if table exists

        Example:
            >>> connector.write_ucids(data, "ucid_scores", if_exists="replace")
        """
        import pandas as pd

        df = pd.DataFrame(ucids)
        df.to_sql(table_name, self.engine, if_exists=if_exists, index=False)

    def read_ucids(self, query: str) -> list[dict[str, Any]]:
        """Read UCID data using a SQL query.

        Args:
            query: SQL query to execute.

        Returns:
            List of dictionaries, one per row.

        Example:
            >>> data = connector.read_ucids("SELECT * FROM ucid_scores LIMIT 100")
        """
        import pandas as pd

        df = pd.read_sql(query, self.engine)
        return df.to_dict("records")

    def close(self) -> None:
        """Close the database connection."""
        self.engine.dispose()
