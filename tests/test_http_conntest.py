from textwrap import dedent


class Test:
    def test_success(
        self,
        processes,
        echo_server_port,
        timeout,
    ):
        with processes.start_wg(
            config=dedent(
                f'''\
                users: []
                targets:
                -   name: target
                    allow_roles: [role]
                    http:
                        url: http://localhost:{echo_server_port}
                '''
            ),
            args=['test-target', 'target'],
        ) as (proc, _):
            proc.wait(timeout=timeout)
            assert proc.returncode == 0

    def test_fail_no_connection(self, processes, timeout):
        with processes.start_wg(
            config=dedent(
                '''\
                users: []
                targets:
                -   name: target
                    allow_roles: [role]
                    http:
                        url: http://localhostbaddomain
                '''
            ),
            args=['test-target', 'target'],
        ) as (proc, _):
            proc.wait(timeout=timeout)
            assert proc.returncode != 0
