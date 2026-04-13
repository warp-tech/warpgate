import requests

from .conftest import ProcessManager
from .util import wait_port, wait_mysql_port


class TestPostgresMigrations:
    def test_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_postgres_server()

        wg = processes.start_wg(
            database_url=f"postgres://user:123@localhost:{db_port}/db",
        )

        wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

        session = requests.Session()
        session.verify = False
        response = session.get(f"https://localhost:{wg.http_port}/@warpgate/api/info")
        assert response.status_code == 200


class TestMysqlMigrations:
    def test_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_mysql_server()
        wait_mysql_port(db_port)

        wg = processes.start_wg(
            database_url=f"mysql://root:123@localhost:{db_port}/db",
        )

        wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

        session = requests.Session()
        session.verify = False
        response = session.get(f"https://localhost:{wg.http_port}/@warpgate/api/info")
        assert response.status_code == 200
