import requests

from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port, wait_mysql_port


def _check_info_endpoint(wg: WarpgateProcess, timeout: int) -> None:
    wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)
    session = requests.Session()
    session.verify = False
    response = session.get(f"https://localhost:{wg.http_port}/@warpgate/api/info")
    assert response.status_code == 200


class TestPostgresMigrations:
    def test_postgres_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_postgres_server()
        wg = processes.start_wg(
            database_url=f"postgres://user:123@localhost:{db_port}/db",
        )
        _check_info_endpoint(wg, timeout)


class TestMysqlMigrations:
    def test_mysql_migrations(self, processes: ProcessManager, timeout):
        db_port = processes.start_plain_mysql_server()
        wait_mysql_port(db_port)
        wg = processes.start_wg(
            database_url=f"mysql://root:123@localhost:{db_port}/warpgate",
        )
        _check_info_endpoint(wg, timeout)
